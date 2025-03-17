use actix_web::{HttpResponse, cookie::Cookie, web};
use authcraft::{
    LoginUserRequest, RegisterUserRequest, User, UserRepository,
    error::AuthError,
    jwt::{JwtConfig, issue_jwt},
    security::verify_password,
};
use sqlx::PgPool;
use validator::Validate;

use crate::{
    models::{error::ApiError, user::PostgresUserRepository},
    utils::validation::{ValidatedLoginUserRequest, ValidatedRegisterUserRequest},
};
pub async fn register(
    pool: web::Data<PgPool>,
    jwt: web::Data<JwtConfig>,
    req: web::Json<ValidatedRegisterUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let repo = PostgresUserRepository::new(pool.get_ref().clone()); // Clone the pool reference
    req.validate().map_err(ApiError::from)?;
    let data: RegisterUserRequest = RegisterUserRequest::from(req.into_inner());
    // Call the repository method and handle errors
    let result: User<()> = repo.create_user(data).await.map_err(|e| {
        // Convert AuthError into an ApiError
        match e {
            AuthError::EmailTaken(_) => ApiError::bad_request("Email already exists"),
            AuthError::DatabaseError(e) => ApiError::internal_server_error(&e),
            _ => ApiError::internal_server_error("Failed to create user"),
        }
    })?;
    let token: String =
        issue_jwt::<()>(jwt.get_ref().clone(), result.id.clone(), None).map_err(|e| match e {
            _ => ApiError::internal_server_error("Failed to create jwt token"),
        })?;
    let cookie = Cookie::build("access_token", token)
        .path("/") // Set cookie for the root path
        .http_only(true) // Prevent JavaScript access (security measure)
        .secure(true) // Send only over HTTPS
        .finish();

    // Return the successful response
    Ok(HttpResponse::Ok().cookie(cookie).json(result))
}

pub async fn login(
    pool: web::Data<PgPool>,
    jwt: web::Data<JwtConfig>,
    req: web::Json<ValidatedLoginUserRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate the login request
    req.validate().map_err(ApiError::from)?;

    // Convert the validated request into a LoginUserRequest
    let data = LoginUserRequest::from(req.into_inner());

    // Initialize the user repository
    let repo = PostgresUserRepository::new(pool.get_ref().clone());

    // Find the user by email
    let result: User<()> = repo
        .find_user_by_email(&data.email)
        .await
        .map_err(|e| match e {
            AuthError::InternalServerError(message) => ApiError::internal_server_error(&message),
            AuthError::UserNotFound(_) => ApiError::not_found("Invalid credentials"),
            _ => ApiError::internal_server_error("Unknown error occurred"),
        })?;

    // Verify the provided password against the stored password hash
    let is_password_valid = verify_password(&data.password, &result.password_hash)
        .map_err(|_| ApiError::unauthorized("Invalid credentials"))?;

    if !is_password_valid {
        return Err(ApiError::unauthorized("Invalid credentials"));
    }

    // Issue a JWT token for the authenticated user
    let token = issue_jwt::<()>(jwt.get_ref().clone(), result.id.clone(), None)
        .map_err(|_| ApiError::internal_server_error("Failed to create JWT token"))?;

    // Create an HTTP-only secure cookie containing the JWT token
    let cookie = Cookie::build("access_token", token)
        .path("/") // Set cookie for the root path
        .http_only(true) // Prevent JavaScript access (security measure)
        .secure(true) // Send only over HTTPS
        .finish();

    // Return a successful response with the cookie and user data
    Ok(HttpResponse::Ok().cookie(cookie).json(result))
}
