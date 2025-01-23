use crate::enrollment_record::EnrollmentRecord;
use crate::proofs::Proof;
use crate::utils::{compute_nonce, compute_x, hash_blind, hash_final, hash_y, sample_nonce};
use std::sync::Arc;

use tokio::sync::RwLock;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng; // Import the trait for `identity()`

use rand::RngCore; // Import the trait for fill_bytes()
use sha2::{Digest, Sha256};
use std::collections::HashMap; // Import the struct

#[derive(Clone)]
pub struct Server {
    secret_key: Aes256Gcm, // AES-GCM encryption key
    ratelimiter_public_key: RistrettoPoint,
    records: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>, // Thread-safe storage
}

impl Server {
    /// Create a new PHE server with a randomly generated AES key
    pub fn new(ratelimiter_public_key: RistrettoPoint) -> Self {
        use rand::RngCore;
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let secret_key = Aes256Gcm::new(&key_bytes.into());

        Self {
            secret_key,
            records: Arc::new(RwLock::new(HashMap::new())), // Thread-safe records
            ratelimiter_public_key: ratelimiter_public_key,
        }
    }
    /// Store an enrollment record into the server
    pub async fn store_enrollment_record(&self, record: EnrollmentRecord) {
        let encrypted_record = self.encrypt_record(&record);
        let mut records = self.records.write().await; // Acquire write lock
        records.insert(record.n, encrypted_record);
    }

    /// Retrieve an enrollment record by username
    pub async fn get_enrollment_record(&self, nonce: &[u8; 32]) -> Option<EnrollmentRecord> {
        let records = self.records.read().await; // Acquire read lock
        let encrypted_record = records.get(nonce)?;
        self.decrypt_record(encrypted_record, nonce)
    }

    /// Encrypt an enrollment record before storing it
    fn encrypt_record(&self, record: &EnrollmentRecord) -> Vec<u8> {
        let nonce = Sha256::digest(record.n); // Derive nonce from username
        let nonce = GenericArray::from_slice(&nonce[..12]); // AES-GCM requires a 12-byte nonce

        let serialized_record = bincode::serialize(record).expect("Failed to serialize");
        self.secret_key
            .encrypt(nonce, serialized_record.as_ref())
            .expect("Encryption failed")
    }

    /// Decrypt an enrollment record when retrieving
    fn decrypt_record(&self, encrypted_data: &[u8], nonce: &[u8; 32]) -> Option<EnrollmentRecord> {
        let nonce = Sha256::digest(nonce); // Derive nonce from username
        let nonce = GenericArray::from_slice(&nonce[..12]);

        let decrypted_bytes = self.secret_key.decrypt(nonce, encrypted_data).ok()?;
        bincode::deserialize(&decrypted_bytes).ok()
    }

    /// Initialize enrollment: generate random nonce, create record, return it
    pub fn encrypt_init(&self) -> (RistrettoPoint, [u8; 32]) {
        // Step 1: Generate a random 32-byte nonce
        let ns = sample_nonce();

        // Step 2: Generate random t_1
        let mut rng = OsRng;
        let m = RistrettoPoint::random(&mut rng); // random key as M

        (m, ns)
    }
    /// Completes the enrollment process
    pub fn encrypt_finish(
        &self,
        password: &str,
        y_0: RistrettoPoint,
        y_1: RistrettoPoint,
        nr: [u8; 32],
        proof: Proof,
        ns: [u8; 32],
        m: RistrettoPoint,
    ) -> EnrollmentRecord {
        // Step 1: Compute `n` as SHA-256(ns, nr)
        let n = compute_nonce(&ns, &nr);

        assert!(
            proof.verify(
                self.ratelimiter_public_key,
                &[hash_y(&n, 0), hash_y(&n, 1)],
                &[y_0, y_1]
            ),
            "Encryption failed: Proof did not verify"
        );

        // Step 2: Compute `x_0` and `x_1` as Ristretto points
        let x_0 = compute_x(password, &n, 0);

        // Step 4: Compute `t_0` as `x_0^{-1} * y_0`
        let t_0 = y_0 - x_0;

        // Step 5: Compute `t_1` as `x_1^{-1} * y_1^{-1} * t_1`
        let t_1 = m - y_1;

        EnrollmentRecord::new(t_0, t_1, n)
    }

    /// Initializes decryption
    pub fn decrypt_init(
        &self,
        record: &EnrollmentRecord,
        challenge_password: &str,
    ) -> (RistrettoPoint, Scalar) {
        // Step 1: Extract nonce `n` from the record
        let n = record.n;

        // Step 2: Compute `h_s_0` and `h_s_1`
        let h_s_0 = compute_x(challenge_password, &n, 0);

        let (t_0, _t_1) = record
            .to_points()
            .expect("Decrypt init: Failed to recover points t_0 and t_1");
        // Step 3: Compute `h_r_0 = t_0 + h_s_0`
        let h_r_0 = t_0 + h_s_0;

        // Step 4: Compute `h_b = hash_blind(h_r_0)`
        let h_b = hash_blind(&h_r_0);

        // Step 5: Sample a random scalar `r_s`
        let r_s = Scalar::random(&mut OsRng);

        // Step 6: Compute `x = h_b ^ r_s`
        let x = h_b * r_s;

        // Step 6: Return `(x, r_s, n)`
        (x, r_s)
    }

    /// Completes the decryption process
    pub fn decrypt_finish(
        &self,
        y_1: RistrettoPoint,
        y_2: RistrettoPoint,
        proof: Proof,
        r_s: Scalar,
        record: &EnrollmentRecord,
    ) -> RistrettoPoint {
        // Step 1: Compute `h_f = hash_final(y_1 * (-r_s))`
        let h_f = hash_final(&(y_1 * (r_s.invert())));

        // Step 2: Compute `h_r_1 = y_2 - h_f`
        let h_r_1 = y_2 - h_f;

        let (_t_0, t_1) = record
            .to_points()
            .expect("Decrypt init: Failed to recover points t_0 and t_1");

        // Step 4: Compute `m = record.t_1 + h_s_1 + h_r_1`
        let m = t_1 + h_r_1;

        assert!(
            proof.verify(
                self.ratelimiter_public_key,
                &[hash_y(&record.n, 1)],
                &[h_r_1]
            ),
            "Encryption failed: Proof did not verify"
        );

        // Step 5: Return `m`
        m
    }
    /// Opt-out: Computes `H(password, n, 0)` and `M` by reversing encryption steps.
    pub fn opt_out(
        &self,
        ratelimiter_secret_key: Scalar,
        record: &EnrollmentRecord,
    ) -> (RistrettoPoint, RistrettoPoint) {
        // Step 1: Extract nonce `n`
        let n = record.n;

        // Step 3: Recover `y_0` using RateLimiter’s secret key
        let y_0 = hash_y(&n, 0) * ratelimiter_secret_key;
        let y_1 = hash_y(&n, 1) * ratelimiter_secret_key;

        // Step 4: Recover `t_0` from the record
        let (t_0, t_1) = record
            .to_points()
            .expect("Opt-out: Failed to recover points t_0 and t_1");

        let x_0_inv = t_0 - y_0;
        let x_0 = -x_0_inv;

        // Step 6: Recover `M = t_1 + y_1`
        let m = t_1 + y_1;

        // Step 7: Return `H(password, n, 0)` and `M`
        (x_0, m)
    }
}
