use actix_web::web;

use crate::services::auth_service::{login, register, verify_email}; // Import the login handler

pub fn auth_routes_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(web::resource("/sign-up").route(web::post().to(register))) // Correct registration
            .service(web::resource("/sign-in").route(web::post().to(login))) // Login endpoint
            .service(web::resource("/verify-email").route(web::get().to(verify_email))), // Verify email
    );
}
