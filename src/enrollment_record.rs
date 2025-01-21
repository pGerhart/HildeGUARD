use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub t_0: [u8; 32], // Store as bytes
    pub t_1: [u8; 32], // Store as bytes
    pub n: [u8; 32],   // SHA-256 output
}

impl EnrollmentRecord {
    /// Convert from Ristretto points to serializable struct
    pub fn new(t_0: RistrettoPoint, t_1: RistrettoPoint, n: [u8; 32]) -> Self {
        Self {
            t_0: t_0.compress().to_bytes(),
            t_1: t_1.compress().to_bytes(),
            n,
        }
    }

    /// Convert back to Ristretto points after deserialization
    pub fn to_points(&self) -> Option<(RistrettoPoint, RistrettoPoint)> {
        let t_0 = CompressedRistretto(self.t_0).decompress()?;
        let t_1 = CompressedRistretto(self.t_1).decompress()?;
        Some((t_0, t_1))
    }
}
