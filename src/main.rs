mod enrollment_record;
mod proofs;
mod ratelimiter;
mod server;
mod utils;

use hex::encode;
use ratelimiter::RateLimiter;
use server::Server;
use utils::{compute_nonce, compute_x, hash_blind};

fn main() {
    // Step 1: Initialize the Server and RateLimiter
    let server = Server::new();
    let ratelimiter = RateLimiter::new();

    // Step 2: Run `enroll_init` on the Server
    let password = "securepassword";
    let (m, ns) = server.enroll_init();
    println!("Server generated nonce: {:?}", encode(ns));

    // Step 3: Forward `ns` to the RateLimiter
    let (y_0, y_1, nr) = ratelimiter.enroll(ns);
    println!("RateLimiter returned y_0, y_1 and nonce nr");

    // Step 4: The Server runs `enroll_finish`
    let final_record = server.enroll_finish(password, y_0, y_1, nr, ns, m);

    // running tests
    // Verify that compute_nonce(ns, nr) matches the stored nonce in the record
    let computed_nonce = compute_nonce(&ns, &nr);
    if computed_nonce == final_record.n {
        println!("Nonce verification successful: computed nonce matches the stored nonce.");
    } else {
        println!("Nonce verification FAILED: computed nonce does not match the stored nonce.");
    }
    let (t_0, t_1) = final_record
        .to_points()
        .expect("Decrypt init: Failed to recover points t_0 and t_1");

    // checking t_0
    let h_s_0 = compute_x(password, &final_record.n, 0);
    if h_s_0 + t_0 == y_0 {
        println!("✅ Verification successful: compute_x(password, n, 0) + final_record.t_0 == y_0");
    } else {
        println!("❌ Verification failed: y_0 mismatch!");
    }
    // ✅ Check t_1
    if t_1 + y_1 == m {
        println!("✅ Verification successful: final_record.t_1 + y_1 == m");
    } else {
        println!("❌ Verification failed: t_1 + y_1 does not match m!");
    }
    //
    //
    // Now Decrypt
    //
    //

    // Step 5: The Server calls `decrypt_init`
    let (x, r_s, n) = server.decrypt_init(&final_record, password);
    println!("Server ran decrypt_init:"); // h_b = {:?}, r_s = {:?}", h_b, r_s);

    // Step 6: The RateLimiter calls `decrypt`
    let (y_1_prime, y_2, h_f_r, r_r) = ratelimiter.decrypt(x, n);
    println!("RateLimiter returned y_1' and y_2");

    // ✅ Check if `y_1' == y_1 * r_s * r_r`
    if y_1_prime * (r_s.invert()) == hash_blind(&y_0) * r_r {
        println!("✅ Verification successful: y_1' matches y_1 * r_s * r_r");
    } else {
        println!("❌ Verification failed: y_1' does not match y_1 * r_s * r_r!");
    }

    // Step 7: The Server calls `decrypt_finish`
    let (m_prime, h_f_s) = server.decrypt_finish(y_1_prime, y_2, r_s, &final_record);
    println!("Server ran decrypt_finish, obtained m'");

    // ✅ Check if `h_f_r` from RateLimiter matches `h_f_s` from Server
    if h_f_r == h_f_s {
        println!("✅ Verification successful: h_f_r from RateLimiter matches h_f_s from Server");
    } else {
        println!("❌ Verification failed: h_f_r does not match h_f_s!");
    }

    // Step 8: Check if `m_prime` matches original `m`
    if m == m_prime {
        println!("Decryption successful! m' matches the original m.");
    } else {
        println!("Decryption failed! m' does not match m.");
    }
}
