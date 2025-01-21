use crate::enrollment_record::EnrollmentRecord;
use crate::utils::{compute_nonce, compute_x, sample_nonce};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng; // Import the trait for `identity()`

use rand::RngCore; // Import the trait for fill_bytes()
use sha2::{Digest, Sha256};
use std::collections::HashMap; // Import the struct
pub struct Server {
    secret_key: Aes256Gcm,             // AES-GCM encryption key
    records: HashMap<String, Vec<u8>>, // username → Encrypted record
}

impl Server {
    /// Create a new PHE server with a randomly generated AES key
    pub fn new() -> Self {
        use rand::RngCore;
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let secret_key = Aes256Gcm::new(&key_bytes.into());

        Self {
            secret_key,
            records: HashMap::new(),
        }
    }
    /// Encrypt an enrollment record before storing it
    fn encrypt_record(&self, record: &EnrollmentRecord, username: &str) -> Vec<u8> {
        let nonce = Sha256::digest(username.as_bytes()); // Derive nonce from username
        let nonce = GenericArray::from_slice(&nonce[..12]); // AES-GCM requires a 12-byte nonce

        let serialized_record = bincode::serialize(record).expect("Failed to serialize");
        self.secret_key
            .encrypt(nonce, serialized_record.as_ref())
            .expect("Encryption failed")
    }

    /// Decrypt an enrollment record when retrieving
    fn decrypt_record(&self, encrypted_data: &[u8], username: &str) -> Option<EnrollmentRecord> {
        let nonce = Sha256::digest(username.as_bytes()); // Derive nonce from username
        let nonce = GenericArray::from_slice(&nonce[..12]);

        let decrypted_bytes = self.secret_key.decrypt(nonce, encrypted_data).ok()?;
        bincode::deserialize(&decrypted_bytes).ok()
    }
    /// Retrieve and decrypt an enrollment record by username
    pub fn get_record(&self, username: &str) -> Option<EnrollmentRecord> {
        self.records
            .get(username)
            .and_then(|enc| self.decrypt_record(enc, username))
    }

    /// Initialize enrollment: generate random nonce, create record, return it
    pub fn enroll_init(&self) -> (RistrettoPoint, [u8; 32]) {
        // Step 1: Generate a random 32-byte nonce
        let ns = sample_nonce();

        // Step 2: Generate random t_1
        let mut rng = OsRng;
        let m = RistrettoPoint::random(&mut rng); // random key as M

        (m, ns)
    }
    /// Completes the enrollment process
    pub fn enroll_finish(
        &self,
        password: &str,
        y_0: RistrettoPoint,
        y_1: RistrettoPoint,
        nr: [u8; 32],
        m: RistrettoPoint,
        ns: [u8; 32],
    ) -> EnrollmentRecord {
        // Step 1: Compute `n` as SHA-256(ns, nr)
        let n = compute_nonce(&ns, &nr);

        // Step 2: Compute `x_0` and `x_1` as Ristretto points
        let x_0 = compute_x(password, &n, 0);
        let x_1 = compute_x(password, &n, 1);

        // Step 4: Compute `t_0` as `x_0^{-1} * y_0`
        let t_0 = y_0 - x_0;

        // Step 5: Compute `t_1` as `x_1^{-1} * y_1^{-1} * t_1`
        let t_1 = m - x_1 - y_1;

        EnrollmentRecord::new(t_0, t_1, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    fn create_random_enrollment_record() -> EnrollmentRecord {
        let mut rng = OsRng;
        let t_0 = RistrettoPoint::random(&mut rng); // Correct way to generate a random point
        let t_1 = RistrettoPoint::random(&mut rng);
        let n = Sha256::digest(b"test_user").into();

        EnrollmentRecord::new(t_0, t_1, n)
    }

    /// Test if the server initializes correctly
    #[test]
    fn test_server_initialization() {
        let server = Server::new();
        assert!(
            server.records.is_empty(),
            "Server should start with no records"
        );
    }

    /// Test encrypting and decrypting an enrollment record
    #[test]
    fn test_encrypt_decrypt_record() {
        let server = Server::new();
        let username = "test_user";
        let record = create_random_enrollment_record();

        let encrypted = server.encrypt_record(&record, username);
        assert!(!encrypted.is_empty(), "Encrypted data should not be empty");

        let decrypted = server.decrypt_record(&encrypted, username);
        assert!(decrypted.is_some(), "Decryption should succeed");

        let decrypted_record = decrypted.unwrap();
        let (orig_t0, orig_t1) = record.to_points().unwrap();
        let (dec_t0, dec_t1) = decrypted_record.to_points().unwrap();

        assert_eq!(orig_t0, dec_t0, "Decrypted t_0 should match original");
        assert_eq!(orig_t1, dec_t1, "Decrypted t_1 should match original");
        assert_eq!(
            record.n, decrypted_record.n,
            "Decrypted nonce should match original"
        );
    }

    /// Test storing and retrieving an enrollment record
    #[test]
    fn test_store_and_retrieve_record() {
        let mut server = Server::new();
        let username = "test_user";
        let record = create_random_enrollment_record();

        // Encrypt and store
        let encrypted_record = server.encrypt_record(&record, username);
        server
            .records
            .insert(username.to_string(), encrypted_record);

        // Retrieve and decrypt
        let retrieved_record = server.get_record(username);
        assert!(retrieved_record.is_some(), "Record should be retrievable");

        let retrieved_record = retrieved_record.unwrap();
        let (orig_t0, orig_t1) = record.to_points().unwrap();
        let (retr_t0, retr_t1) = retrieved_record.to_points().unwrap();

        assert_eq!(orig_t0, retr_t0, "Retrieved t_0 should match original");
        assert_eq!(orig_t1, retr_t1, "Retrieved t_1 should match original");
        assert_eq!(
            record.n, retrieved_record.n,
            "Retrieved nonce should match original"
        );
    }

    /// Test retrieval of a non-existent user
    #[test]
    fn test_retrieve_nonexistent_record() {
        let server = Server::new();
        let record = server.get_record("unknown_user");
        assert!(record.is_none(), "Should return None for nonexistent users");
    }
}
