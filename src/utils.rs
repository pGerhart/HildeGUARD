#![allow(dead_code)]

use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512}; // Import the trait for `identity()` // Import the trait for fill_bytes()

/// Compute nonce `n` as SHA-256 of `ns` and `nr`
pub fn compute_nonce(ns: &[u8; 32], nr: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ns);
    hasher.update(nr);
    hasher.finalize().into()
}

/// Compute `x_i` as SHA-512(password, n, i) and directly hash into the Ristretto group
pub fn compute_x(password: &str, n: &[u8; 32], i: u8) -> RistrettoPoint {
    let mut hasher = Sha512::new(); // Use SHA-512
    hasher.update(password.as_bytes());
    hasher.update(n);
    hasher.update(&[i]); // Append i (either 0 or 1)

    let hash_output = hasher.finalize(); // Now 64 bytes

    // Directly hash into the Ristretto group
    RistrettoPoint::hash_from_bytes::<Sha512>(&hash_output)
}

/// Compute `y_i_0` as SHA-512(n, i) and directly hash into the Ristretto group
pub fn hash_y(n: &[u8; 32], i: u8) -> RistrettoPoint {
    let mut hasher = Sha512::new(); // Use SHA-512
    hasher.update(n);
    hasher.update(&[i]); // Append i (either 0 or 1)

    let hash_output = hasher.finalize(); // Now 64 bytes

    // Directly hash into the Ristretto group
    RistrettoPoint::hash_from_bytes::<Sha512>(&hash_output)
}

pub fn sample_nonce() -> [u8; 32] {
    let mut ns = [0u8; 32];
    OsRng.fill_bytes(&mut ns); // Fill ns with cryptographic random bytes
    ns
}

/// used for blinding during decryption
pub fn hash_blind(point: &RistrettoPoint) -> RistrettoPoint {
    hash_point(point)
}

/// used for blinding during decryption
pub fn hash_final(point: &RistrettoPoint) -> RistrettoPoint {
    hash_point(point)
}

/// Hashes a RistrettoPoint into another RistrettoPoint
fn hash_point(point: &RistrettoPoint) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(point.compress().as_bytes()); // Hash compressed bytes

    RistrettoPoint::hash_from_bytes::<Sha512>(&hasher.finalize())
}
