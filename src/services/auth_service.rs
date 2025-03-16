use actix_web::{HttpResponse, cookie::Cookie, post, web};
use authcraft::{
    RegisterUserRequest, User, UserRepository,
    error::AuthError,
    jwt::{JwtConfig, issue_jwt},
};
use sqlx::PgPool;

use crate::models::{error::ApiError, user::PostgresUserRepository};
#[post("/sign-up")]
async fn register(
    pool: web::Data<PgPool>,
    jwt: web::Data<JwtConfig>,
    req: web::Json<RegisterUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let repo = PostgresUserRepository::new(pool.get_ref().clone()); // Clone the pool reference

    // Call the repository method and handle errors
    let result: User<()> = repo.create_user(req.into_inner()).await.map_err(|e| {
        // Convert AuthError into an ApiError
        match e {
            AuthError::EmailTaken => ApiError::bad_request("Email or username already exists"),
            AuthError::DatabaseError => ApiError::internal_server_error("Database error"),
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
