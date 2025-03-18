use actix_web::{App, HttpServer, middleware::Logger, web};
use config::Config;
use routes::auth_routes::auth_routes_config;
mod auth;
mod config;
mod models;
mod routes;
mod services;
mod utils;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = Config::from_env().await;
    // Initialize the logger
    env_logger::init();
    HttpServer::new(move || {
        App::new()
            .service(web::scope("/api").configure(auth_routes_config))
            .app_data(web::Data::new(config.pool.clone()))
            .app_data(web::Data::new(config.jwt.clone()))
            .app_data(web::Data::new(config.email_service.clone()))
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
