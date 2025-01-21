use std::os::macos::raw::stat;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

/// Struct representing a Schnorr proof
#[derive(Debug, Clone)]
pub struct Proof {
    c: Scalar,
    s: Scalar,
}

impl Proof {
    /// Generate a Schnorr proof of exponentiation
    pub fn proof(
        sk: Scalar,
        pk: RistrettoPoint,
        statement: RistrettoPoint,
        basis: RistrettoPoint,
    ) -> Self {
        // Step 1: Sample a random scalar `r`
        let r = Scalar::random(&mut OsRng);
        let com_r = RistrettoPoint::mul_base(&r); // G * secret_key
        let com_base = basis * r;

        // Step 3: Compute `c = SHA-256(pk, R, statement)`, interpreted as a scalar
        let c = Self::compute_challenge(pk, com_r, com_base, statement);

        // Step 4: Compute `s = sk * c + r`
        let s = (sk * c) + r;

        // Step 5: Return proof `(c, s)`
        Self { c, s }
    }

    /// Verify a Schnorr proof
    pub fn verify(
        &self,
        pk: RistrettoPoint,
        statement: RistrettoPoint,
        basis: RistrettoPoint,
    ) -> bool {
        let com_r_prime: RistrettoPoint = RistrettoPoint::mul_base(&self.s) - (pk * self.c);
        let com_base_prime: RistrettoPoint = (basis * self.s) - (statement * self.c);

        // Step 2: Compute `c' = SHA-256(pk, R', statement)`, interpreted as a scalar
        let c_prime = Self::compute_challenge(pk, com_r_prime, com_base_prime, statement);

        // Step 3: Proof is valid if `c' == c`
        self.c == c_prime
    }

    /// Compute the challenge `c = SHA-256(pk, R, statement)`
    fn compute_challenge(
        pk: RistrettoPoint,
        R: RistrettoPoint,
        Com: RistrettoPoint,
        statement: RistrettoPoint,
    ) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(pk.compress().as_bytes());
        hasher.update(R.compress().as_bytes());
        hasher.update(Com.compress().as_bytes());
        hasher.update(statement.compress().as_bytes());
        Scalar::from_hash(hasher)
    }
}

#[cfg(test)]
mod tests {
    use crate::proofs::Proof;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn test_valid_proof() {
        // Generate a keypair
        let sk = Scalar::random(&mut rand::thread_rng());
        let pk = RistrettoPoint::mul_base(&sk);

        // Define a basis and statement
        let basis = RistrettoPoint::mul_base(&Scalar::random(&mut rand::thread_rng()));
        let statement = basis * sk; // g^sk

        // Generate proof
        let proof = Proof::proof(sk, pk, statement, basis);

        // Verify proof
        assert!(proof.verify(pk, statement, basis), "Proof should be valid");
    }

    #[test]
    fn test_invalid_proof() {
        // Generate keypair
        let sk = Scalar::random(&mut rand::thread_rng());
        let pk = RistrettoPoint::mul_base(&sk);

        // Define a basis and statement
        let basis = RistrettoPoint::mul_base(&Scalar::random(&mut rand::thread_rng()));
        let statement = basis * sk;

        // Generate proof with correct values
        let proof = Proof::proof(sk, pk, statement, basis);

        // Modify proof by changing `s`
        let invalid_proof = Proof {
            c: proof.c,
            s: proof.s + Scalar::ONE, // Introduce an error
        };

        // Verification should fail
        assert!(
            !invalid_proof.verify(pk, statement, basis),
            "Tampered proof should be invalid"
        );
    }

    #[test]
    fn test_invalid_public_key() {
        // Generate two different keypairs
        let sk1 = Scalar::random(&mut rand::thread_rng());
        let pk1 = RistrettoPoint::mul_base(&sk1);

        let sk2 = Scalar::random(&mut rand::thread_rng());
        let pk2 = RistrettoPoint::mul_base(&sk2); // Different public key

        // Define a basis and statement
        let basis = RistrettoPoint::mul_base(&Scalar::random(&mut rand::thread_rng()));
        let statement = basis * sk1; // g^sk1

        // Generate proof with first keypair
        let proof = Proof::proof(sk1, pk1, statement, basis);

        // Verification should fail with incorrect public key
        assert!(
            !proof.verify(pk2, statement, basis),
            "Verification with incorrect public key should fail"
        );
    }

    #[test]
    fn test_invalid_statement() {
        // Generate keypair
        let sk = Scalar::random(&mut rand::thread_rng());
        let pk = RistrettoPoint::mul_base(&sk);

        // Define a basis and statement
        let basis = RistrettoPoint::mul_base(&Scalar::random(&mut rand::thread_rng()));
        let statement = basis * sk;

        // Generate proof with correct values
        let proof = Proof::proof(sk, pk, statement, basis);

        // Create an incorrect statement
        let wrong_statement = basis * Scalar::random(&mut rand::thread_rng()); // Different statement

        // Verification should fail
        assert!(
            !proof.verify(pk, wrong_statement, basis),
            "Verification with incorrect statement should fail"
        );
    }
}
