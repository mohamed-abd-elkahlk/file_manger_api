use authcraft::jwt::JwtConfig;
use dotenv::dotenv;
use sqlx::PgPool;
use std::env;
pub struct Config {
    pub database_url: String,
    pub jwt: JwtConfig,
    pub pool: PgPool,
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

        Self {
            database_url,
            jwt,
            pool,
        }
    }
}
