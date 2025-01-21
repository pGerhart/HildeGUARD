mod enrollment_record;
mod ratelimiter;
mod server;
mod utils;

use ratelimiter::RateLimiter;
use server::Server;

fn main() {
    // Step 1: Initialize the Server and RateLimiter
    let server = Server::new();
    let ratelimiter = RateLimiter::new();

    // Step 2: Run `enroll_init` on the Server
    let password = "securepassword";
    let (m, ns) = server.enroll_init();
    println!("Server generated nonce: {:?}", hex::encode(ns));

    // Step 3: Forward `ns` to the RateLimiter
    let (y_0, y_1, nr) = ratelimiter.enroll_init(ns);
    println!("RateLimiter returned y_0, y_1 and nonce nr");

    // Step 4: The Server runs `enroll_finish`
    let final_record = server.enroll_finish(password, y_0, y_1, nr, m, ns);
    println!("Final Enrollment Record: {:?}", final_record);
}
