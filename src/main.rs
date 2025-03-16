use actix_web::{App, HttpResponse, HttpServer, Responder, get, middleware::Logger, post, web};
use config::Config;
use services::auth_service::register;
mod auth;
mod config;
mod models;
mod routes;
mod services;
#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}
#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = Config::from_env().await;
    // Initialize the logger
    env_logger::init();
    HttpServer::new(move || {
        App::new()
            .service(hello)
            .service(echo)
            .service(register)
            .route("/hey", web::get().to(manual_hello))
            .app_data(web::Data::new(config.pool.clone()))
            .app_data(web::Data::new(config.jwt.clone()))
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
