use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use authcraft::error::AuthError;
use std::fmt;
use validator::ValidationErrors;

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
impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::UserNotFound(msg) => ApiError::not_found(&msg),
            AuthError::InvalidCredentials(msg) => ApiError::unauthorized(&msg),
            AuthError::TokenExpired(msg) => ApiError::unauthorized(&msg),
            AuthError::InvalidToken(msg) => ApiError::unauthorized(&msg),
            AuthError::Unauthorized(msg) => ApiError::unauthorized(&msg),
            AuthError::AccountLocked(msg) => ApiError::unauthorized(&msg),
            AuthError::AccountDisabled(msg) => ApiError::unauthorized(&msg),
            AuthError::PasswordTooWeak(msg) => ApiError::bad_request(&msg),
            AuthError::PasswordResetRequired(msg) => ApiError::bad_request(&msg),
            AuthError::TokenNotProvided(msg) => ApiError::bad_request(&msg),
            AuthError::TokenCreationFailed(msg) => ApiError::internal_server_error(&msg),
            AuthError::TokenVerificationFailed(msg) => ApiError::internal_server_error(&msg),
            AuthError::TokenRevoked(msg) => ApiError::unauthorized(&msg),
            AuthError::SessionExpired(msg) => ApiError::unauthorized(&msg),
            AuthError::SessionNotFound(msg) => ApiError::not_found(&msg),
            AuthError::TooManySessions(msg) => ApiError::bad_request(&msg),
            AuthError::EmailTaken(msg) => ApiError::bad_request(&msg),
            AuthError::InvalidUsername(msg) => ApiError::bad_request(&msg),
            AuthError::RegistrationDisabled(msg) => ApiError::bad_request(&msg),
            AuthError::BruteForceAttempt(msg) => ApiError::unauthorized(&msg),
            AuthError::SuspiciousActivity(msg) => ApiError::unauthorized(&msg),
            AuthError::TwoFactorAuthRequired(msg) => ApiError::unauthorized(&msg),
            AuthError::TwoFactorAuthFailed(msg) => ApiError::unauthorized(&msg),
            AuthError::DatabaseError(msg) => ApiError::internal_server_error(&msg),
            AuthError::ConfigurationError(msg) => ApiError::internal_server_error(&msg),
            AuthError::InternalServerError(msg) => ApiError::internal_server_error(&msg),
            AuthError::CustomError(msg) => ApiError::internal_server_error(&msg),
            AuthError::HashingError(msg) => ApiError::internal_server_error(&msg),
            AuthError::RateLimitExceeded(msg) => ApiError::too_many_requests(&msg),
            AuthError::ThirdPartyServiceError(msg) => ApiError::internal_server_error(&msg),
            AuthError::InvalidSecret(msg) => ApiError::unauthorized(&msg),
            AuthError::InvalidOtp(msg) => ApiError::unauthorized(&msg),
            AuthError::InvalidBackupCode(msg) => ApiError::unauthorized(&msg),
        }
    }
}

impl From<ValidationErrors> for ApiError {
    fn from(errors: ValidationErrors) -> Self {
        let error_messages: Vec<String> = errors
            .field_errors()
            .iter()
            .flat_map(|(field, errs)| {
                errs.iter().map(move |err| {
                    format!(
                        "{}: {}",
                        field.to_uppercase(),
                        err.message
                            .clone()
                            .unwrap_or_else(|| "Invalid input".into())
                    )
                })
            })
            .collect();
        let message = error_messages.join(", ");
        println!("{:?},{:?}", error_messages, message);
        ApiError::bad_request(&message)
    }
}
