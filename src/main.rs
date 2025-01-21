mod enrollment_record;
mod proofs;
pub mod ratelimiter;
pub mod server;
pub mod utils;

use hex::encode;
use ratelimiter::RateLimiter;
use server::Server;
use utils::{compute_nonce, compute_x, hash_blind};

fn main() {
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
    use crate::ratelimiter::RateLimiter;
    use crate::server::Server;
    use crate::utils::{compute_nonce, compute_x, hash_blind};

    #[cfg(test)]
    mod tests {
        use crate::ratelimiter::RateLimiter;
        use crate::server::Server;
        use crate::utils::compute_x;

        #[test]
        fn test_opt_out() {
            // Step 1: Initialize the Server and RateLimiter
            let ratelimiter = RateLimiter::new();
            let server = Server::new(ratelimiter.public_key);

            // Step 2: Run `encrypt_init` on the Server
            let password = "securepassword";
            let (m, ns) = server.encrypt_init();

            // Step 3: Forward `ns` to the RateLimiter
            let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);

            // Step 4: The Server runs `encrypt_finish`
            let final_record = server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m);

            // Step 5: The Server calls `decrypt_init`
            let (x, r_s) = server.decrypt_init(&final_record, password);

            // Step 6: The RateLimiter calls `decrypt`
            let (y_1_prime, y_2, proof_decrypt) = ratelimiter.decrypt(x, final_record.n);

            // Step 7: The Server calls `decrypt_finish`
            let m_prime = server.decrypt_finish(y_1_prime, y_2, proof_decrypt, r_s, &final_record);

            // Step 8: Check if `m_prime` matches original `m`
            assert_eq!(m, m_prime, "Decryption failed! m' does not match m.");

            // Step 9: Opt-Out Process
            let (x_opt, m_opt) = server.opt_out(ratelimiter.secret_key, &final_record);

            // Step 10: Verify that `opt_out` reconstructed `M` correctly
            assert_eq!(m, m_opt, "Opt out message failed! m' does not match m.");

            // Step 11: Verify that `opt_out` correctly reconstructed `H(password, n, 0)`
            let expected_x = compute_x(password, &final_record.n, 0);
            assert_eq!(
                expected_x, x_opt,
                "Opt out hash failed! x' does not match x."
            );
        }
    }

    #[test]
    fn test_full_encrypt_decrypt_workflow() {
        // Step 1: Initialize the Server and RateLimiter
        let ratelimiter = RateLimiter::new();
        let server = Server::new(ratelimiter.public_key);

        // Step 2: Run `encrypt_init` on the Server
        let password = "securepassword";
        let (m, ns) = server.encrypt_init();
        println!("Server generated nonce: {:?}", ns);

        // Step 3: Forward `ns` to the RateLimiter
        let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);
        println!("RateLimiter returned y_0, y_1 and nonce nr");

        // Step 4: The Server runs `encrypt_finish`
        let final_record = server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m);

        // Step 5: The Server calls `decrypt_init`
        let (x, r_s) = server.decrypt_init(&final_record, password);
        println!("Server ran decrypt_init");

        // Step 6: The RateLimiter calls `decrypt`
        let (y_1_prime, y_2, proof_decrypt) = ratelimiter.decrypt(x, final_record.n);
        println!("RateLimiter returned y_1' and y_2");

        // Step 7: The Server calls `decrypt_finish`
        let m_prime = server.decrypt_finish(y_1_prime, y_2, proof_decrypt, r_s, &final_record);
        println!("Server ran decrypt_finish, obtained m'");

        // Step 8: Check if `m_prime` matches original `m`
        assert_eq!(m, m_prime, "Decryption failed! m' does not match m.");
        println!("Decryption successful! m' matches the original m.");
    }
}
