use crate::enrollment_record::EnrollmentRecord;
use crate::proofs::Proof;
use crate::ratelimiter::RateLimiter;
use crate::server::Server;
use crate::utils::compute_x;
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct EnrollRequest {
    password: String,
}

#[derive(Serialize, Deserialize)]
struct EnrollResponse {
    record: String, // Serialized enrollment record
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct DecryptRequest {
    record: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct DecryptResponse {
    success: bool,
    m: String, // Return `m_prime` as a hex string
}

#[derive(Serialize, Deserialize)]
struct OptOutRequest {
    record: String,
}

#[derive(Serialize, Deserialize)]
struct OptOutResponse {
    x_opt: String,
    m_opt: String,
}

// Shared server instance
struct AppState {
    server: Server,
    ratelimiter_public_key: RistrettoPoint, // Store the public key
}

/// Fetch the RateLimiter’s public key and return it as a `RistrettoPoint`
async fn fetch_ratelimiter_public_key() -> RistrettoPoint {
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8081/public-key")
        .send()
        .await
        .expect("Failed to fetch RateLimiter public key")
        .json::<serde_json::Value>()
        .await
        .expect("Invalid response format");

    let public_key_bytes =
        hex::decode(response["public_key"].as_str().unwrap()).expect("Invalid public key format");

    let compressed =
        CompressedRistretto::from_slice(&public_key_bytes).expect("Invalid RistrettoPoint format");

    compressed
        .decompress()
        .expect("Failed to decompress RistrettoPoint")
}

// Enrollment Endpoint
#[post("/enroll")]
async fn enroll(data: web::Data<AppState>, req: web::Json<EnrollRequest>) -> impl Responder {
    let password = req.password.clone();
    let (m, ns) = data.server.encrypt_init();

    // Communicate with RateLimiter
    let client = reqwest::Client::new();
    let encrypt_response = client
        .post("http://127.0.0.1:8081/encrypt")
        .json(&serde_json::json!({ "nonce": hex::encode(&ns) }))
        .send()
        .await;

    if let Ok(response) = encrypt_response {
        if let Ok(body) = response.json::<serde_json::Value>().await {
            // Convert hex strings to the correct types
            let y_0 = match hex::decode(body["y_0"].as_str().unwrap()) {
                Ok(bytes) => CompressedRistretto::from_slice(&bytes)
                    .map(|c| c.decompress())
                    .ok()
                    .flatten()
                    .expect("Invalid y_0 RistrettoPoint"),
                Err(_) => return HttpResponse::BadRequest().body("Invalid y_0 format"),
            };
            let y_1 = match hex::decode(body["y_1"].as_str().unwrap()) {
                Ok(bytes) => CompressedRistretto::from_slice(&bytes)
                    .map(|c| c.decompress())
                    .ok()
                    .flatten()
                    .expect("Invalid y_1 RistrettoPoint"),
                Err(_) => return HttpResponse::BadRequest().body("Invalid y_1 format"),
            };
            let nr = match hex::decode(body["nr"].as_str().unwrap()) {
                Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
                _ => return HttpResponse::BadRequest().body("Invalid nr format"),
            };
            let pi = match hex::decode(body["pi"].as_str().unwrap()) {
                Ok(bytes) if bytes.len() == 64 => Proof::from_bytes(&bytes).expect("Invalid proof"),
                _ => return HttpResponse::BadRequest().body("Invalid proof format"),
            };

            let final_record = data
                .server
                .encrypt_finish(&password, y_0, y_1, nr, pi, ns, m);
            return HttpResponse::Ok().json(EnrollResponse {
                record: serde_json::to_string(&final_record).unwrap(),
                nonce: hex::encode(ns),
            });
        }
    }

    HttpResponse::InternalServerError().finish()
}

/// Decryption Endpoint
#[post("/decrypt")]
async fn decrypt(data: web::Data<AppState>, req: web::Json<DecryptRequest>) -> impl Responder {
    let record: EnrollmentRecord = serde_json::from_str(&req.record).unwrap();
    let password = req.password.clone();

    let (x, r_s) = data.server.decrypt_init(&record, &password);

    let client = reqwest::Client::new();
    let decrypt_response = client
        .post("http://127.0.0.1:8081/rate-limit")
        .json(&serde_json::json!({
            "x": hex::encode(x.compress().to_bytes()),
            "nonce": hex::encode(&record.n)
        }))
        .send()
        .await;

    if let Ok(response) = decrypt_response {
        if let Ok(body) = response.json::<serde_json::Value>().await {
            let y_1_prime = match hex::decode(body["y_1_prime"].as_str().unwrap()) {
                Ok(bytes) => CompressedRistretto::from_slice(&bytes)
                    .map(|c| c.decompress())
                    .ok()
                    .flatten()
                    .expect("Invalid y_1_prime RistrettoPoint"),
                Err(_) => return HttpResponse::BadRequest().body("Invalid y_1_prime format"),
            };

            let y_2 = match hex::decode(body["y_2"].as_str().unwrap()) {
                Ok(bytes) => CompressedRistretto::from_slice(&bytes)
                    .map(|c| c.decompress())
                    .ok()
                    .flatten()
                    .expect("Invalid y_2 RistrettoPoint"),
                Err(_) => return HttpResponse::BadRequest().body("Invalid y_2 format"),
            };

            let pi = match hex::decode(body["pi"].as_str().unwrap()) {
                Ok(bytes) if bytes.len() == 64 => Proof::from_bytes(&bytes).expect("Invalid proof"),
                _ => return HttpResponse::BadRequest().body("Invalid proof format"),
            };

            let m_prime = data.server.decrypt_finish(y_1_prime, y_2, pi, r_s, &record);

            return HttpResponse::Ok().json(DecryptResponse {
                success: true,                                 //TODO: for production do handling
                m: hex::encode(m_prime.compress().to_bytes()), // Convert `m_prime` to hex
            });
        }
    }

    HttpResponse::InternalServerError().finish()
}

/// Start the Actix Web Server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let ratelimiter_public_key = fetch_ratelimiter_public_key().await;

    let server = Server::new(ratelimiter_public_key.clone());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                server: server.clone(),
                ratelimiter_public_key: ratelimiter_public_key.clone(),
            }))
            .service(enroll)
            .service(decrypt)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
