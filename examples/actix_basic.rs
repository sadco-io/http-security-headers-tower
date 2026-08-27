//! Simple Actix-Web integration using a preset.
//!
//! Run with:
//!
//! ```text
//! cargo run --example actix_basic --features actix
//! ```

use actix_web::{web, App, HttpResponse, HttpServer};
use http_security_headers::{Preset, SecurityHeadersMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server running on http://127.0.0.1:3000");
    println!("Security headers applied: Preset::Strict");
    println!("\nTry:");
    println!("  curl -I http://127.0.0.1:3000/");

    HttpServer::new(|| {
        App::new()
            .wrap(SecurityHeadersMiddleware::new(Preset::Strict.build()))
            .route(
                "/",
                web::get().to(|| async { HttpResponse::Ok().body("Hello, World!") }),
            )
            .route(
                "/health",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            )
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}
