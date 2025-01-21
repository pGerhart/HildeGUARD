use crate::proofs::Proof;
use crate::utils::{compute_nonce, hash_blind, hash_final, hash_y, sample_nonce};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::{self, Scalar};
use rand::rngs::OsRng;
use std::collections::HashMap; // Import the trait for `identity()`
pub struct RateLimiter {
    secret_key: Scalar,                     // Secret key (private)
    pub public_key: RistrettoPoint,         // Public key (G * secret_key)
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

    fn compute_prfs(
        &self,
        nonce: [u8; 32],
    ) -> (
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
    ) {
        // Step 3: Compute `y_0` and `y_1`
        let hash_0 = hash_y(&nonce, 0);
        let hash_1 = hash_y(&nonce, 1);

        let y_0 = hash_0 * self.secret_key; // y_0 = hash(n, 0)^skr
        let y_1 = hash_1 * self.secret_key; // y_1 = hash(n, 1)^skr

        (y_0, hash_0, y_1, hash_1)
    }

    /// Initialize enrollment: computes `y_0`, `y_1`, and `nr`
    pub fn encrypt(&self, ns: [u8; 32]) -> (RistrettoPoint, RistrettoPoint, Proof, [u8; 32]) {
        // Step 1: Sample a random nonce `nr`
        let nr = sample_nonce();

        // Step 2: Compute final nonce `n`
        let n = compute_nonce(&ns, &nr);

        let (y_0, hash_0, y_1, hash_1) = self.compute_prfs(n);

        let proof = Proof::proof(
            self.secret_key,
            self.public_key,
            &[hash_0, hash_1],
            &[y_0, y_1],
        );

        // Step 4: Return computed values
        (y_0, y_1, proof, nr)
    }

    pub fn decrypt(
        &self,
        x: RistrettoPoint,
        n: [u8; 32],
    ) -> (
        RistrettoPoint,
        RistrettoPoint,
        Proof,
        RistrettoPoint,
        Scalar,
    ) {
        // Step 1: Compute `h_r_0` and `h_r_1` from `n` using the PRF
        let (h_r_0, _hash_0, h_r_1, hash_1) = self.compute_prfs(n);

        let proof = Proof::proof(self.secret_key, self.public_key, &[hash_1], &[h_r_1]);

        // Step 2: Compute `h_b` as a blind hash of `h_r_0`
        let h_b = hash_blind(&h_r_0);

        // Step 3: Sample a random scalar `r_r`
        let r_r = Scalar::random(&mut OsRng);

        // Step 4: Compute `y_1 = x * r_r`, introducing randomness
        let y_1 = x * r_r;
        let h_f = hash_final(&(h_b * r_r));

        // Step 5: Compute `y_2 = hash_final(h_b * r_r) + h_r_1`
        let y_2 = h_f + h_r_1;

        // Step 6: Return the computed `(y_1, y_2)`
        (y_1, y_2, proof, h_f, r_r)
    }
}
