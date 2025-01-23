use crate::ratelimiter::RateLimiter;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use curve25519_dalek::ristretto::CompressedRistretto;
use hex;
use serde::{Deserialize, Serialize};

/// Structs for API serialization
#[derive(Serialize, Deserialize)]
struct EncryptRequest {
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptResponse {
    y_0: String,
    y_1: String,
    nr: String,
    pi: String,
}

#[derive(Serialize, Deserialize)]
struct DecryptRequest {
    x: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct DecryptResponse {
    y_1_prime: String,
    y_2: String,
    pi: String,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    public_key: String,
}

// Implement Clone for RateLimiter (so it can be stored in AppState)
#[derive(Clone)]
struct AppState {
    ratelimiter: RateLimiter,
}

/// Endpoint to get the RateLimiter's public key
#[get("/public-key")]
async fn public_key(data: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(PublicKeyResponse {
        public_key: hex::encode(data.ratelimiter.public_key.compress().to_bytes()),
    })
}

#[post("/encrypt")]
async fn encrypt(data: web::Data<AppState>, req: web::Json<EncryptRequest>) -> impl Responder {
    let ns_vec = match hex::decode(&req.nonce) {
        Ok(n) if n.len() == 32 => n,
        _ => return HttpResponse::BadRequest().body("Invalid nonce format"),
    };

    // Convert Vec<u8> to [u8; 32]
    let ns: [u8; 32] = match ns_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::InternalServerError().body("Nonce conversion failed"),
    };

    let (y_0, y_1, pi, nr) = data.ratelimiter.encrypt(ns);

    HttpResponse::Ok().json(EncryptResponse {
        y_0: hex::encode(y_0.compress().to_bytes()),
        y_1: hex::encode(y_1.compress().to_bytes()),
        nr: hex::encode(nr),
        pi: hex::encode(pi),
    })
}

/// Rate-Limited Decryption Endpoint
#[post("/rate-limit")]
async fn rate_limit(data: web::Data<AppState>, req: web::Json<DecryptRequest>) -> impl Responder {
    // Decode `x` from hex and convert it to a `RistrettoPoint`
    let x_bytes = match hex::decode(&req.x) {
        Ok(b) if b.len() == 32 => b,
        _ => return HttpResponse::BadRequest().body("Invalid x format"),
    };
    let x = match CompressedRistretto::from_slice(&x_bytes) {
        Ok(compressed) => match compressed.decompress() {
            Some(point) => point,
            None => return HttpResponse::BadRequest().body("Invalid RistrettoPoint"),
        },
        Err(_) => return HttpResponse::BadRequest().body("Invalid x format"),
    };
    // Decode `nonce` and ensure it's a `[u8; 32]` array
    let nonce_vec = match hex::decode(&req.nonce) {
        Ok(n) if n.len() == 32 => n,
        _ => return HttpResponse::BadRequest().body("Invalid nonce format"),
    };
    let nonce: [u8; 32] = match nonce_vec.try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::InternalServerError().body("Nonce conversion failed"),
    };

    // Call the `decrypt` method with the correct types
    let (y_1_prime, y_2, proof) = data.ratelimiter.decrypt(x, nonce);

    HttpResponse::Ok().json(DecryptResponse {
        y_1_prime: hex::encode(y_1_prime.compress().to_bytes()),
        y_2: hex::encode(y_2.compress().to_bytes()),
        pi: hex::encode(proof.to_bytes()),
    })
}

/// Start the Actix Web RateLimiter Server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let ratelimiter = RateLimiter::new();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                ratelimiter: ratelimiter.clone(),
            }))
            .service(public_key)
            .service(encrypt)
            .service(rate_limit)
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}
