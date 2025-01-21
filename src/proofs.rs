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
    /// Generate a Schnorr proof for multiple bases and statements
    pub fn proof(
        sk: Scalar,
        pk: RistrettoPoint,
        bases: &[RistrettoPoint],      // A set of bases
        statements: &[RistrettoPoint], // A set of statements
    ) -> Self {
        assert_eq!(
            bases.len(),
            statements.len(),
            "Mismatched bases and statements length"
        );

        // Step 1: Sample a random scalar `r`
        let r = Scalar::random(&mut OsRng);
        let com_r = RistrettoPoint::mul_base(&r); // G^r

        // Step 2: Compute `com_base` for each base-statement pair
        let com_bases: Vec<RistrettoPoint> = bases.iter().map(|base| base * r).collect();

        // Step 3: Compute `c = SHA-256(pk, com_r, com_bases, statements)`, interpreted as a scalar
        let c = Self::compute_challenge(pk, com_r, &com_bases, statements);

        // Step 4: Compute `s = sk * c + r`
        let s = (sk * c) + r;

        // Step 5: Return proof `(c, s)`
        Self { c, s }
    }

    /// Verify a Schnorr proof for multiple bases and statements
    pub fn verify(
        &self,
        pk: RistrettoPoint,
        bases: &[RistrettoPoint],
        statements: &[RistrettoPoint],
    ) -> bool {
        assert_eq!(
            bases.len(),
            statements.len(),
            "Mismatched bases and statements length"
        );

        // Step 1: Compute `com_r' = G^s - pk * c`
        let com_r_prime: RistrettoPoint = RistrettoPoint::mul_base(&self.s) - (pk * self.c);

        let com_bases_prime: Vec<RistrettoPoint> = statements
            .iter()
            .zip(bases.iter()) // Ensures correct pairing
            .map(|(statement, base)| (base * self.s) - (statement * self.c))
            .collect();

        // Step 3: Compute `c' = SHA-256(pk, com_r', com_bases', statements)`, interpreted as a scalar
        let c_prime = Self::compute_challenge(pk, com_r_prime, &com_bases_prime, statements);

        // Step 4: Proof is valid if `c' == c`
        self.c == c_prime
    }

    /// Compute the challenge `c = SHA-256(pk, com_r, com_bases, statements)`
    fn compute_challenge(
        pk: RistrettoPoint,
        com_r: RistrettoPoint,
        com_bases: &[RistrettoPoint],
        statements: &[RistrettoPoint],
    ) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(pk.compress().as_bytes());
        hasher.update(com_r.compress().as_bytes());

        for com in com_bases {
            hasher.update(com.compress().as_bytes());
        }

        for statement in statements {
            hasher.update(statement.compress().as_bytes());
        }

        Scalar::from_hash(hasher)
    }
}

#[cfg(test)]
mod tests {
    use crate::proofs::Proof;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    #[test]
    fn test_valid_proof_multiple_bases() {
        // Generate a keypair
        let sk = Scalar::random(&mut rand::thread_rng());
        let pk = RistrettoPoint::mul_base(&sk);

        // Define multiple bases and statements
        let bases: Vec<RistrettoPoint> = (0..10)
            .map(|_| RistrettoPoint::mul_base(&Scalar::random(&mut rand::thread_rng())))
            .collect();

        let statements: Vec<RistrettoPoint> = bases.iter().map(|b| b * sk).collect();

        // Generate proof
        let proof = Proof::proof(sk, pk, &bases, &statements);

        // Verify proof
        assert!(
            proof.verify(pk, &bases, &statements),
            "Multi-basis proof should be valid"
        );
    }

    #[test]
    fn test_invalid_proof_multiple_bases() {
        // Generate a keypair
        let sk = Scalar::random(&mut rand::thread_rng());
        let pk = RistrettoPoint::mul_base(&sk);

        // Define multiple bases and statements
        let bases: Vec<RistrettoPoint> = (0..3)
            .map(|_| RistrettoPoint::mul_base(&Scalar::random(&mut rand::thread_rng())))
            .collect();

        let statements: Vec<RistrettoPoint> = bases.iter().map(|b| b * sk).collect();

        // Generate proof
        let proof = Proof::proof(sk, pk, &bases, &statements);

        // Modify proof by changing `s`
        let invalid_proof = Proof {
            c: proof.c,
            s: proof.s + Scalar::ONE, // Introduce an error
        };

        // Verification should fail
        assert!(
            !invalid_proof.verify(pk, &statements, &bases),
            "Tampered multi-basis proof should be invalid"
        );
    }
}
