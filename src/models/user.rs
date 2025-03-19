use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use authcraft::{
    RegisterUserRequest, Role, UpdateUser, User, UserRepository,
    error::AuthError,
    jwt::{Claims, JwtConfig, issue_jwt, verify_jwt},
    mfa::{MfaSettings, MfaType},
    security::{
        RequestPasswordResetRequest, ResetPasswordRequest, generate_reset_token, hash_password,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, prelude::FromRow, types::time::OffsetDateTime};
use uuid::Uuid;
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct AppUser {
    pub user: User<()>,
}
pub struct AppUserMetaData {}
pub struct PostgresUserRepository {
    pool: PgPool,
}
impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
#[async_trait]
impl<U: Send + Sync + serde::de::DeserializeOwned + 'static + std::marker::Unpin> UserRepository<U>
    for PostgresUserRepository
where
    U: Default,
{
    async fn find_user_by_id(&self, id: &str) -> Result<User<U>, AuthError> {
        let id =
            uuid::Uuid::parse_str(id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let row = sqlx::query!(
            "SELECT id, username, email, is_verified, password_hash, role FROM users WHERE id = $1",
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::UserNotFound(e.to_string()))?;

        Ok(User {
            id: row.id.to_string(),
            username: row.username,
            email: row.email,
            is_verified: false,
            password_hash: row.password_hash,
            role: Role::User,
            data: None, // Since `User<()>` has no extra data
            mfa_enabled: false,
            mfa_type: None,
            totp_secret: None,
            email_otp: None,
            backup_codes: None,
            mfa_recovery_codes_used: None,
            password_reset_token: None,
            password_reset_expiry: None,
            email_verification_token: None,
            email_verification_expiry: None,
            last_login_at: None,
            failed_login_attempts: 0,
            account_locked_until: None,
            refresh_token: None,
            refresh_token_expiry: None,
            last_password_change: None,
            password_history: None,
        })
    }
    async fn find_user_by_email(&self, email: &str) -> Result<User<U>, AuthError> {
        let row = sqlx::query!(
            "SELECT id, username, email, password_hash, is_verified,  role FROM users WHERE email = $1",
            email
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::UserNotFound(e.to_string()))?;
        // Return the created user
        Ok(User {
            id: row.id.to_string(),
            username: row.username,
            email: row.email,
            is_verified: false,
            password_hash: row.password_hash,
            role: Role::User,
            data: None, // Since `User<()>` has no extra data
            mfa_enabled: false,
            mfa_type: None,
            totp_secret: None,
            email_otp: None,
            backup_codes: None,
            mfa_recovery_codes_used: None,
            password_reset_token: None,
            password_reset_expiry: None,
            email_verification_token: None,
            email_verification_expiry: None,
            last_login_at: None,
            failed_login_attempts: 0,
            account_locked_until: None,
            refresh_token: None,
            refresh_token_expiry: None,
            last_password_change: None,
            password_history: None,
        })
    }
    async fn create_user(&self, user: RegisterUserRequest) -> Result<User<U>, AuthError> {
        // Hash the password, propagating any hashing errors
        let password_hash =
            hash_password(&user.password).map_err(|e| AuthError::HashingError(e.to_string()))?;

        // Check if email is already taken
        let email_exists = sqlx::query!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) as exists",
            user.email
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if email_exists.exists.unwrap_or(false) {
            return Err(AuthError::EmailTaken(format!(
                "Email {} is already in use",
                user.email
            )));
        }

        // Insert the new user
        let row = sqlx::query!(
        "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id",
        user.username,
        user.email,
        password_hash,
        "User" // Default role as a string
    )
    .fetch_one(&self.pool)
    .await
    .map_err(|e| {
        // Check for unique constraint violations which might be missed by the initial check
        if e.to_string().contains("unique constraint") || e.to_string().contains("duplicate key") {
            if e.to_string().contains("email") {
                AuthError::EmailTaken(format!("Email {} is already in use", user.email))
            } else if e.to_string().contains("username") {
                AuthError::InvalidUsername(format!("Username {} is already in use", user.username))
            } else {
                AuthError::DatabaseError(format!("Database constraint violation: {}", e))
            }
        } else {
            AuthError::DatabaseError(format!("Failed to create user: {}", e))
        }
    })?;

        // Return the created user
        Ok(User {
            id: row.id.to_string(),
            username: user.username,
            email: user.email,
            is_verified: false,
            password_hash,
            role: Role::User,
            data: None, // Since `User<()>` has no extra data
            mfa_enabled: false,
            mfa_type: None,
            totp_secret: None,
            email_otp: None,
            backup_codes: None,
            mfa_recovery_codes_used: None,
            password_reset_token: None,
            password_reset_expiry: None,
            email_verification_token: None,
            email_verification_expiry: None,
            last_login_at: None,
            failed_login_attempts: 0,
            account_locked_until: None,
            refresh_token: None,
            refresh_token_expiry: None,
            last_password_change: None,
            password_history: None,
        })
    }
    async fn update_user(&self, user: UpdateUser<U>) -> Result<User<U>, AuthError> {
        let id = uuid::Uuid::from_str(&user.id)
            .map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        // Fetch the existing user to merge updates
        let existing_user: User<U> = self.find_user_by_id(&user.id).await?;

        let username = user.username.unwrap_or(existing_user.username);
        let email = user.email.unwrap_or(existing_user.email);
        let password_hash = match &user.password {
            Some(password) if !password.is_empty() => hash_password(password)?, // Only hash if a new, non-empty password is provided
            _ => existing_user.password_hash, // Keep the existing hash
        };
        let role = user.role.unwrap_or(existing_user.role);

        let role_str = match role {
            Role::Admin => "Admin",
            Role::User => "User",
            Role::Guest => "Guest",
        };

        let result = sqlx::query!(
            "UPDATE users SET username = $1, email = $2, password_hash = $3, role = $4 WHERE id = $5",
            username,
            email,
            password_hash,
            role_str,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("user not found".to_string()));
        }

        // Return the updated user
        self.find_user_by_id(&user.id).await
    }

    async fn delete_user(&self, id: &str) -> Result<(), AuthError> {
        let id =
            uuid::Uuid::from_str(id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }
    async fn create_verification_token(
        &self,
        email: &str,
        jwt: JwtConfig,
    ) -> Result<(String, User<U>), AuthError> {
        let user: User<U> = self.find_user_by_email(email.into()).await?;
        let token: String = issue_jwt(jwt, email.to_string(), Some(()))?;
        Ok((token, user))
    }
    async fn verify_email(&self, token: &str, jwt: JwtConfig) -> Result<Claims<U>, AuthError> {
        let token: Claims<U> =
            verify_jwt(&jwt, token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        Ok(token)
    }

    async fn mark_user_as_verified(&self, user_id: &str) -> Result<(), AuthError> {
        let id = uuid::Uuid::from_str(&user_id)
            .map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let result = sqlx::query!("UPDATE users SET is_verified = TRUE WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }

        Ok(())
    }
    async fn enable_mfa(&self, user_id: &str, method: MfaType) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let method_json = serde_json::to_string(&method)
            .map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let user_record = sqlx::query!(
            "UPDATE users
             SET mfa_enabled = $1, mfa_type = $2 
             WHERE id = $3",
            true,
            &method_json,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if user_record.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }
    async fn disable_mfa(&self, user_id: &str) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let user_record = sqlx::query!(
            "UPDATE users
             SET mfa_enabled = $1 
             WHERE id = $2",
            false,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if user_record.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }
    async fn update_totp_secret(&self, user_id: &str, secret: String) -> Result<String, AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        sqlx::query!(
            "UPDATE users SET totp_secret = $1 WHERE id = $2",
            secret,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(secret)
    }
    async fn generate_backup_codes(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        // Generate backup codes using MfaSettings
        let backup_codes = MfaSettings::generate_backup_codes(10, 6);

        sqlx::query!(
            "UPDATE users SET backup_codes = $1 WHERE id = $2",
            &backup_codes,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(backup_codes)
    }
    async fn use_backup_code(&self, user_id: &str, code: String) -> Result<(), AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let user = sqlx::query!(
            "SELECT mfa_enabled, backup_codes, totp_secret FROM users WHERE id = $1",
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // If MFA is disabled, return an error
        if !user.mfa_enabled {
            return Err(AuthError::ConfigurationError(
                "User must enable MFA first to use this feature".to_string(),
            ));
        }

        // Create an MfaSettings instance with user's backup codes
        let mut mfa_settings = MfaSettings {
            method: MfaType::Email, // Assuming Email for backup codes
            secret: user.totp_secret.clone(),
            backup_codes: user.backup_codes.clone(),
        };

        // Verify backup code
        if mfa_settings.verify_backup_code(&code).is_ok() {
            // Mark the code as used
            mfa_settings.mark_backup_code_as_used(&code)?;

            // Update the backup codes in the database
            sqlx::query!(
                "UPDATE users SET backup_codes = $1 WHERE id = $2",
                &mfa_settings.backup_codes.unwrap_or_default(),
                id
            )
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            return Ok(()); // Backup code successfully used
        }

        Err(AuthError::InvalidBackupCode(
            "Invalid backup code".to_string(),
        ))
    }

    // Password reset methods
    async fn forgot_password(&self, req: RequestPasswordResetRequest) -> Result<(), AuthError> {
        let email = req.email;
        let password_reset_token = generate_reset_token();
        // Set expiry time (e.g., 15 minutes from now)
        let expiry_time = OffsetDateTime::now_utc() + Duration::from_secs(15 * 60);

        let result = sqlx::query!(
            "UPDATE users SET password_reset_token = $1, password_reset_expiry = $2 WHERE email = $3",
            password_reset_token,
            expiry_time,
            &email
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }

    async fn verify_reset_token(&self, user_id: &str, token: &str) -> Result<bool, AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        // Fetch the stored token and expiry time from the database
        let user = sqlx::query!(
            "SELECT password_reset_token, password_reset_expiry FROM users WHERE id = $1",
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Check if a token exists and matches the provided one
        if let Some(stored_token) = user.password_reset_token {
            if stored_token == token {
                // Check if the token is still valid (not expired)
                if let Some(expiry_time) = user.password_reset_expiry {
                    if OffsetDateTime::now_utc() <= expiry_time {
                        return Ok(true); // Token is valid
                    } else {
                        return Err(AuthError::InvalidOtp("Reset token has expired".to_string()));
                    }
                }
            }
        }

        Err(AuthError::InvalidOtp("Invalid reset token".to_string()))
    }
    async fn reset_password(
        &self,
        user_id: &str,
        req: ResetPasswordRequest,
    ) -> Result<(), AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        // Fetch the reset token and expiry time
        let user = sqlx::query!(
            "SELECT password_reset_token, password_reset_expiry FROM users WHERE id = $1",
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Validate token
        if let Some(stored_token) = user.password_reset_token {
            if stored_token != req.token {
                return Err(AuthError::InvalidOtp("Invalid reset token".to_string()));
            }

            if let Some(expiry_time) = user.password_reset_expiry {
                if OffsetDateTime::now_utc() > expiry_time {
                    return Err(AuthError::InvalidOtp("Reset token has expired".to_string()));
                }
            } else {
                return Err(AuthError::InvalidOtp(
                    "No expiry time found for reset token".to_string(),
                ));
            }
        } else {
            return Err(AuthError::InvalidOtp("No reset token found".to_string()));
        }

        // Hash the new password
        let hashed_password =
            hash_password(&req.new_password).map_err(|e| AuthError::HashingError(e.to_string()))?;

        // Update password and remove reset token
        sqlx::query!(
        "UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expiry = NULL WHERE id = $2",
        hashed_password,
        id
    )
    .execute(&self.pool)
    .await
    .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    // Session management methods
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let time = OffsetDateTime::now_utc();
        let result = sqlx::query!(
            "UPDATE users SET last_login_at = $1 WHERE id = $2",
            time,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }
    async fn increment_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let result = sqlx::query!(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + $1 WHERE id = $2",
            1,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }
    async fn reset_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let result = sqlx::query!(
            "UPDATE users SET failed_login_attempts = $1 WHERE id = $2",
            0,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }
    async fn lock_account(&self, user_id: &str, until: SystemTime) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let until = OffsetDateTime::from(until);

        let result = sqlx::query!(
            "UPDATE users SET locked = $1,locked_until=$2 WHERE id = $3",
            true,
            until,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }
    async fn unlock_account(&self, user_id: &str) -> Result<(), AuthError> {
        let id =
            Uuid::from_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let result = sqlx::query!("UPDATE users SET locked = $1 WHERE id = $2", false, id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }
        Ok(())
    }

    async fn update_refresh_token(
        &self,
        user_id: &str,
        token: String,
        expiry: SystemTime,
    ) -> Result<(), AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let expiry = OffsetDateTime::from(expiry);

        sqlx::query!(
            "UPDATE users SET refresh_token = $1, refresh_token_expiry = $2 WHERE id = $3",
            token,
            expiry,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }
    async fn clear_refresh_token(&self, user_id: &str) -> Result<(), AuthError> {
        let id =
            Uuid::parse_str(user_id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        sqlx::query!(
            "UPDATE users SET refresh_token = NULL, refresh_token_expiry = NULL WHERE id = $1",
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    // Security methods
    async fn update_password_history(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError> {
        let id = uuid::Uuid::parse_str(user_id)
            .map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let result = sqlx::query!(
            "UPDATE users SET password_history = password_history || ARRAY[$1] WHERE id = $2",
            password_hash,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        // Check if the user was found and updated
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }

        Ok(())
    }

    async fn update_last_password_change(&self, user_id: &str) -> Result<(), AuthError> {
        let time = OffsetDateTime::now_utc();
        let uuid = uuid::Uuid::parse_str(user_id)
            .map_err(|e| AuthError::InternalServerError(e.to_string()))?;

        let result = sqlx::query!(
            "UPDATE users SET last_password_change = $1 WHERE id = $2",
            time,
            uuid
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Check if the user was found and updated
        if result.rows_affected() == 0 {
            return Err(AuthError::UserNotFound("User not found".to_string()));
        }

        Ok(())
    }
}
