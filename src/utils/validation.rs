use authcraft::{LoginUserRequest, RegisterUserRequest, Role, UpdateUser};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct ValidatedRegisterUserRequest {
    #[validate(length(min = 3, max = 50, message = "must be between 3 and 50 characters"))]
    pub username: String,

    #[validate(email(message = "Must be a valid email address"))]
    pub email: String,

    #[validate(
        length(min = 8, message = "Password must be at least 8 characters"),
        custom(function = "validate_password_strength")
    )]
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct ValidatedLoginUserRequest {
    #[validate(email(message = "Must be a valid email address"))]
    pub email: String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct ValidatedUpdateUser<T> {
    pub id: String,

    #[validate(length(min = 3, max = 50, message = "must be between 3 and 50 characters"))]
    #[validate(custom(function = "validate_optional_field"))]
    pub username: Option<String>,

    #[validate(email(message = "Must be a valid email address"))]
    #[validate(custom(function = "validate_optional_field"))]
    pub email: Option<String>,

    #[validate(length(min = 8, message = "Must be at least 8 characters"))]
    #[validate(custom(function = "validate_password_strength"))]
    pub password: Option<String>,

    pub role: Option<Role>,
    pub data: Option<T>,
}

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_letter = password.chars().any(|c| c.is_alphabetic());

    if !has_digit || !has_letter {
        let mut error = ValidationError::new("weak_password");
        error.message = Some("must contain at least one letter and one digit".into());
        return Err(error);
    }

    Ok(())
}

fn validate_optional_field(field: &String) -> Result<(), ValidationError> {
    if field.is_empty() {
        return Err(ValidationError::new("Field cannot be empty if provided"));
    }
    Ok(())
}

// Conversion functions
impl From<ValidatedRegisterUserRequest> for RegisterUserRequest {
    fn from(validated: ValidatedRegisterUserRequest) -> Self {
        Self {
            username: validated.username,
            email: validated.email,
            password: validated.password,
        }
    }
}

impl From<ValidatedLoginUserRequest> for LoginUserRequest {
    fn from(validated: ValidatedLoginUserRequest) -> Self {
        Self {
            email: validated.email,
            password: validated.password,
        }
    }
}

impl<T> From<ValidatedUpdateUser<T>> for UpdateUser<T> {
    fn from(validated: ValidatedUpdateUser<T>) -> Self {
        Self {
            id: validated.id,
            username: validated.username,
            email: validated.email,
            password: validated.password,
            role: validated.role,
            data: validated.data,
        }
    }
}
