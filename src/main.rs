mod enrollment_record;
mod proofs;
pub mod ratelimiter;
pub mod server;
pub mod utils;
use rayon::prelude::*;
use std::time::Instant; // Import Rayon for parallelism

use hex::encode;
use rand::{distributions::Alphanumeric, Rng};
use ratelimiter::RateLimiter;
use server::Server;
use sha2::{Digest, Sha256};
use utils::{compute_nonce, compute_x, hash_blind};

const PASSWORD_COUNT: usize = 1_000_000;
const PASSWORD_LENGTH: usize = 12;

fn main() {
    enroll_and_verify_hashed_passwords();
}

fn generate_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(PASSWORD_LENGTH)
        .map(char::from)
        .collect()
}

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    encode(hasher.finalize()) // Convert to hex string
}
fn enroll_and_verify_hashed_passwords() {
    let ratelimiter = RateLimiter::new();
    let server = Server::new(ratelimiter.public_key);

    // Step 1: Generate and hash passwords (without measuring time)
    let passwords: Vec<String> = (0..PASSWORD_COUNT).map(|_| generate_password()).collect();
    let hashed_passwords: Vec<String> = passwords.iter().map(|pw| hash_password(pw)).collect();

    // Step 2: Encrypt all passwords in parallel and measure time
    let start_encrypt = Instant::now();
    let records: Vec<_> = hashed_passwords
        .par_iter() // Rayon parallel iterator
        .map(|hashed_password| {
            let (m, ns) = server.encrypt_init();
            let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);
            let record = server.encrypt_finish(hashed_password, y_0, y_1, nr, encrypt_proof, ns, m);
            (record, m, hashed_password.clone()) // Store record, message, and password
        })
        .collect();
    let encrypt_duration = start_encrypt.elapsed();

    // Step 3: Verify all passwords in parallel and measure time
    let start_verify = Instant::now();
    records.par_iter().for_each(|(record, m, hashed_password)| {
        let (x, r_s) = server.decrypt_init(record, hashed_password);
        let (y_1_prime, y_2, proof_decrypt) = ratelimiter.decrypt(x, record.n);
        let m_prime = server.decrypt_finish(y_1_prime, y_2, proof_decrypt, r_s, record);

        assert_eq!(
            *m, m_prime,
            "Decryption failed for password: {}",
            hashed_password
        );
    });
    let verify_duration = start_verify.elapsed();

    // Print results
    println!("Successfully enrolled and verified 1000 hashed passwords.");
    println!(
        "Parallel encryption time: {:.3?} seconds",
        encrypt_duration.as_secs_f64()
    );
    println!(
        "Average encryption time per password: {:.6?} ms",
        (encrypt_duration.as_secs_f64() * 1000.0) / PASSWORD_COUNT as f64
    );
    println!(
        "Parallel verification time: {:.3?} seconds",
        verify_duration.as_secs_f64()
    );
    println!(
        "Average verification time per password: {:.6?} ms",
        (verify_duration.as_secs_f64() * 1000.0) / PASSWORD_COUNT as f64
    );
}

fn full_run() {
    // Step 1: Initialize the Server and RateLimiter
    let ratelimiter = RateLimiter::new();
    let server = Server::new(ratelimiter.public_key);

    // Step 2: Run `enroll_init` on the Server
    let password = "securepassword";
    let (m, ns) = server.encrypt_init();
    println!("Server generated nonce: {:?}", encode(ns));

    // Step 3: Forward `ns` to the RateLimiter
    let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);
    println!("RateLimiter returned y_0, y_1 and nonce nr");

    // Step 4: The Server runs `enroll_finish`
    let final_record = server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m);

    // Step 5: The Server calls `decrypt_init`
    let (x, r_s) = server.decrypt_init(&final_record, password);
    println!("Server ran decrypt_init:"); // h_b = {:?}, r_s = {:?}", h_b, r_s);

    // Step 6: The RateLimiter calls `decrypt`
    let (y_1_prime, y_2, proof_decrypt) = ratelimiter.decrypt(x, final_record.n);
    println!("RateLimiter returned y_1' and y_2");

    // Step 7: The Server calls `decrypt_finish`
    let m_prime = server.decrypt_finish(y_1_prime, y_2, proof_decrypt, r_s, &final_record);
    println!("Server ran decrypt_finish, obtained m'");

    // Step 8: Check if `m_prime` matches original `m`
    if m == m_prime {
        println!("Decryption successful! m' matches the original m.");
    } else {
        println!("Decryption failed! m' does not match m.");
    }

    let (x_opt, m_opt) = server.opt_out(ratelimiter.secret_key, &final_record);

    if m == m_opt {
        println!("Opt out message successful! m' matches the original m.");
    } else {
        println!("Opt out message failed! m' does not match m.");
    }

    if compute_x(password, &final_record.n, 0) == x_opt {
        println!("Opt out hash successful! x' matches the original x.");
    } else {
        println!("Opt out hash failed! x' does not match x.");
    }
}
#[cfg(test)]
mod tests {
    use crate::enrollment_record::EnrollmentRecord;
    use crate::ratelimiter::RateLimiter;
    use crate::server::Server;
    use crate::utils::{compute_x, sample_nonce};
    use curve25519_dalek::ristretto::RistrettoPoint;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_store_and_retrieve_record() {
        let ratelimiter = RateLimiter::new();
        let server = Server::new(ratelimiter.public_key);

        let ns = sample_nonce();
        let record =
            EnrollmentRecord::new(RistrettoPoint::default(), RistrettoPoint::default(), ns);

        server.store_enrollment_record(record.clone()).await;
        let retrieved = server.get_enrollment_record(&ns).await;

        assert!(retrieved.is_some(), "Stored record should be retrievable");
        assert_eq!(
            retrieved.unwrap().n,
            record.n,
            "Retrieved record nonce should match"
        );
    }

    #[tokio::test]
    async fn test_enrollment_and_decryption() {
        let ratelimiter = RateLimiter::new();
        let server = Server::new(ratelimiter.public_key);

        let password = "securepassword";
        let (m, ns) = server.encrypt_init();

        let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);
        let record = server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m);

        let (x, r_s) = server.decrypt_init(&record, password);
        let (y_1_prime, y_2, proof_decrypt) = ratelimiter.decrypt(x, record.n);
        let m_prime = server.decrypt_finish(y_1_prime, y_2, proof_decrypt, r_s, &record);

        assert_eq!(m, m_prime, "Decryption failed: m' does not match m.");
    }

    #[tokio::test]
    async fn test_opt_out() {
        let ratelimiter = RateLimiter::new();
        let server = Server::new(ratelimiter.public_key);

        let password = "securepassword";
        let (m, ns) = server.encrypt_init();

        let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);
        let record = server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m);

        let (x_opt, m_opt) = server.opt_out(ratelimiter.secret_key, &record);

        assert_eq!(m, m_opt, "Opt-out failed: m_opt does not match m.");
        let expected_x = compute_x(password, &record.n, 0);
        assert_eq!(
            expected_x, x_opt,
            "Opt-out hash failed: x' does not match x."
        );
    }
}
