use std::str::FromStr;

use async_trait::async_trait;
use authcraft::{
    RegisterUserRequest, Role, UpdateUser, User, UserRepository, error::AuthError,
    security::hash_password,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, prelude::FromRow};
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct AppUser {
    pub user: User<()>,
}

pub struct PostgresUserRepository {
    pool: PgPool,
}
impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
#[async_trait]
impl<U: Send + Sync + 'static> UserRepository<U> for PostgresUserRepository {
    async fn find_user_by_id(&self, id: &str) -> Result<User<U>, AuthError> {
        let id =
            uuid::Uuid::parse_str(id).map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        let row = sqlx::query!(
            "SELECT id, username, email, password_hash, role FROM users WHERE id = $1",
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::UserNotFound(e.to_string()))?;
        Ok(User {
            id: row.id.to_string(),
            username: row.username,
            email: row.email,
            password_hash: row.password_hash,
            role: row
                .role
                .as_deref() // Converts `Option<String>` to `Option<&str>`
                .map(|r| match r {
                    "Admin" => Role::Admin,
                    "User" => Role::User,
                    "Guest" => Role::Guest,
                    _ => Role::Guest,
                })
                .unwrap_or(Role::Guest), // Default to Guest
            data: None,
        })
    }

    async fn find_user_by_email(&self, email: &str) -> Result<User<U>, AuthError> {
        let row = sqlx::query!(
            "SELECT id, username, email, password_hash,  role FROM users WHERE email = $1",
            email
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::UserNotFound(e.to_string()))?;
        Ok(User {
            id: row.id.to_string(),
            username: row.username,
            email: row.email,
            password_hash: row.password_hash,
            role: row
                .role
                .as_deref() // Converts `Option<String>` to `Option<&str>`
                .map(|r| match r {
                    "Admin" => Role::Admin,
                    "User" => Role::User,
                    "Guest" => Role::Guest,
                    _ => Role::Guest,
                })
                .unwrap_or(Role::Guest), // Default to Guest
            data: None,
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
            password_hash,
            role: Role::User,
            data: None, // Since `User<()>` has no extra data
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
}
