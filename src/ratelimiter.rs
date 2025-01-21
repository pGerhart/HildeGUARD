use crate::utils::{compute_nonce, hash_y, sample_nonce};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::collections::HashMap; // Import the trait for `identity()`
pub struct RateLimiter {
    secret_key: Scalar,                     // Secret key (private)
    public_key: RistrettoPoint,             // Public key (G * secret_key)
    login_counters: HashMap<[u8; 32], u32>, // Nonce → login attempt count
}

impl RateLimiter {
    /// Creates a new rate limiter with a fresh DLog keypair
    pub fn new() -> Self {
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let public_key = RistrettoPoint::mul_base(&secret_key); // G * secret_key

        Self {
            secret_key,
            public_key,
            login_counters: HashMap::new(),
        }
    }

    /// Increments the login counter for a given nonce
    pub fn increment_login(&mut self, nonce: [u8; 32]) {
        let counter = self.login_counters.entry(nonce).or_insert(0);
        *counter += 1;
    }

    /// Gets the current login count for a given nonce
    pub fn get_login_count(&self, nonce: [u8; 32]) -> u32 {
        *self.login_counters.get(&nonce).unwrap_or(&0)
    }
    /// Initialize enrollment: computes `y_0`, `y_1`, and `nr`
    pub fn enroll_init(&self, ns: [u8; 32]) -> (RistrettoPoint, RistrettoPoint, [u8; 32]) {
        // Step 1: Sample a random nonce `nr`
        let nr = sample_nonce();

        // Step 2: Compute final nonce `n`
        let n = compute_nonce(&ns, &nr);

        // Step 3: Compute `y_0` and `y_1`
        let hash_0 = hash_y(&n, 0);
        let hash_1 = hash_y(&n, 1);

        let y_0 = hash_0 * self.secret_key; // y_0 = hash(n, 0)^skr
        let y_1 = hash_1 * self.secret_key; // y_1 = hash(n, 1)^skr

        // Step 4: Return computed values
        (y_0, y_1, nr)
    }
}
