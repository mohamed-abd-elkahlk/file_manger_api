use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use authcraft::error::AuthError;
use std::fmt;

#[derive(Debug)]
pub struct ApiError {
    message: String,
    code: u16,
    status: String,
}

impl ApiError {
    /// Create a new ApiError
    pub fn new(message: &str, code: u16, status: &str) -> Self {
        Self {
            message: message.to_string(),
            code,
            status: status.to_string(),
        }
    }

    /// Create a 400 Bad Request error
    pub fn bad_request(message: &str) -> Self {
        Self::new(message, 400, "Bad Request")
    }

    /// Create a 401 Unauthorized error
    pub fn unauthorized(message: &str) -> Self {
        Self::new(message, 401, "Unauthorized")
    }

    /// Create a 404 Not Found error
    pub fn not_found(message: &str) -> Self {
        Self::new(message, 404, "Not Found")
    }

    /// Create a 500 Internal Server Error error
    pub fn internal_server_error(message: &str) -> Self {
        Self::new(message, 500, "Internal Server Error")
    }

    /// Create a 429 Too Many Requests error
    pub fn too_many_requests(message: &str) -> Self {
        Self::new(message, 429, "Too Many Requests")
    }
}

/// Implement Display for ApiError to enable logging
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiError {{ message: {}, code: {}, status: {} }}",
            self.message, self.code, self.status
        )
    }
}

/// Implement std::error::Error for ApiError
impl std::error::Error for ApiError {}

/// Implement ResponseError for ApiError to integrate with Actix
impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "message": self.message,
            "code": self.code,
            "status": self.status,
        }))
    }
}

/// Implement From<AuthError> for ApiError
impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::UserNotFound => ApiError::not_found("User not found"),
            AuthError::InvalidCredentials => ApiError::unauthorized("Invalid credentials"),
            AuthError::TokenExpired => ApiError::unauthorized("Token expired"),
            AuthError::InvalidToken => ApiError::unauthorized("Invalid token"),
            AuthError::Unauthorized => ApiError::unauthorized("Unauthorized"),
            AuthError::AccountLocked => ApiError::unauthorized("Account locked"),
            AuthError::AccountDisabled => ApiError::unauthorized("Account disabled"),
            AuthError::PasswordTooWeak => ApiError::bad_request("Password is too weak"),
            AuthError::PasswordResetRequired => ApiError::bad_request("Password reset required"),
            AuthError::TokenNotProvided => ApiError::bad_request("Token not provided"),
            AuthError::TokenCreationFailed => {
                ApiError::internal_server_error("Token creation failed")
            }
            AuthError::TokenVerificationFailed => {
                ApiError::internal_server_error("Token verification failed")
            }
            AuthError::TokenRevoked => ApiError::unauthorized("Token revoked"),
            AuthError::SessionExpired => ApiError::unauthorized("Session expired"),
            AuthError::SessionNotFound => ApiError::not_found("Session not found"),
            AuthError::TooManySessions => ApiError::bad_request("Too many active sessions"),
            AuthError::EmailTaken => ApiError::bad_request("Email is already taken"),
            AuthError::InvalidEmail => ApiError::bad_request("Invalid email address"),
            AuthError::InvalidUsername => ApiError::bad_request("Invalid username"),
            AuthError::RegistrationDisabled => ApiError::bad_request("Registration is disabled"),
            AuthError::BruteForceAttempt => ApiError::unauthorized("Brute force attempt detected"),
            AuthError::SuspiciousActivity => ApiError::unauthorized("Suspicious activity detected"),
            AuthError::TwoFactorAuthRequired => {
                ApiError::unauthorized("Two-factor authentication required")
            }
            AuthError::TwoFactorAuthFailed => {
                ApiError::unauthorized("Two-factor authentication failed")
            }
            AuthError::DatabaseError => ApiError::internal_server_error("Database error"),
            AuthError::ConfigurationError => ApiError::internal_server_error("Configuration error"),
            AuthError::InternalServerError => {
                ApiError::internal_server_error("Internal server error")
            }
            AuthError::CustomError(msg) => ApiError::internal_server_error(&msg),
            AuthError::HashingError(msg) => ApiError::internal_server_error(&msg),
            AuthError::RateLimitExceeded => ApiError::too_many_requests("Rate limit exceeded"),
            AuthError::ThirdPartyServiceError => {
                ApiError::internal_server_error("Third-party service error")
            }
        }
    }
}
