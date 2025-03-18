use authcraft::{
    email::{EmailConfig, EmailService},
    jwt::JwtConfig,
};
use dotenv::dotenv;
use sqlx::PgPool;
use std::env;
pub struct Config {
    pub jwt: JwtConfig,
    pub pool: PgPool,
    pub email_service: EmailService,
}
impl Config {
    pub async fn from_env() -> Self {
        dotenv().ok(); // Load environment variables from .env file
        unsafe {
            env::set_var("RUST_LOG", "debug");
        }
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let expiration_days = env::var("JWT_EXPIRATION_DAYS")
            .expect("JWT_EXPIRATION_DAYS must be set")
            .parse()
            .expect("JWT_EXPIRATION_DAYS must be a number");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to create database pool");
        let jwt = JwtConfig::new(secret, expiration_days);

        // Load email configuration from environment variables
        let email_config = EmailConfig {
            smtp_server: env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
            smtp_username: env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
            smtp_password: env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
            sender_email: env::var("SENDER_EMAIL").expect("SENDER_EMAIL must be set"),
            sender_name: env::var("SENDER_NAME").expect("SENDER_NAME must be set"),
        };
        let email_service = EmailService::new(
            email_config,
            "/home/mohemd/Projects/backend/file_manger/src/views",
        )
        .unwrap();
        Self {
            jwt,
            pool,
            email_service,
        }
    }
}
