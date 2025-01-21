extern crate hildeguard; // Replace with your actual crate name

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use hildeguard::proofs::Proof;
use hildeguard::ratelimiter::RateLimiter;
use hildeguard::server::Server;
use hildeguard::utils::{compute_nonce, compute_x, hash_blind};
use rand::rngs::OsRng;

/// Benchmark the encryption and decryption workflow
fn bench_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encrypt-Decrypt Workflow");

    let ratelimiter = RateLimiter::new();
    let server = Server::new(ratelimiter.public_key);
    let password = "securepassword";

    // Benchmark encryption initialization
    group.bench_function("Server encrypt_init", |b| {
        b.iter(|| {
            let (_m, _ns) = black_box(server.encrypt_init());
        })
    });

    // Benchmark rate limiter encryption
    let (m, ns) = server.encrypt_init();
    group.bench_function("RateLimiter encrypt", |b| {
        b.iter(|| {
            let (_y_0, _y_1, _encrypt_proof, _nr) = black_box(ratelimiter.encrypt(ns));
        })
    });

    let (y_0, y_1, encrypt_proof, nr) = ratelimiter.encrypt(ns);
    group.bench_function("Server encrypt_finish", |b| {
        b.iter(|| {
            black_box(server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m));
        })
    });

    let final_record = server.encrypt_finish(password, y_0, y_1, nr, encrypt_proof, ns, m);
    group.bench_function("Server decrypt_init", |b| {
        b.iter(|| {
            black_box(server.decrypt_init(&final_record, password));
        })
    });

    let (x, r_s) = server.decrypt_init(&final_record, password);
    group.bench_function("RateLimiter decrypt", |b| {
        b.iter(|| {
            black_box(ratelimiter.decrypt(x, final_record.n));
        })
    });

    let (y_1_prime, y_2, proof_decrypt) = ratelimiter.decrypt(x, final_record.n);
    group.bench_function("Server decrypt_finish", |b| {
        b.iter(|| {
            black_box(server.decrypt_finish(y_1_prime, y_2, proof_decrypt, r_s, &final_record));
        })
    });
    group.bench_function("Opt-Out", |b| {
        b.iter(|| {
            black_box(server.opt_out(ratelimiter.secret_key, &final_record));
        })
    });

    group.finish();
}

/// Benchmark the Schnorr proof generation and verification
fn bench_schnorr_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Schnorr Proofs");

    let sk = Scalar::random(&mut OsRng);
    let pk = RistrettoPoint::mul_base(&sk);
    let bases: Vec<RistrettoPoint> = (0..1)
        .map(|_| RistrettoPoint::mul_base(&Scalar::random(&mut OsRng)))
        .collect();
    let statements: Vec<RistrettoPoint> = bases.iter().map(|b| b * sk).collect();

    group.bench_function("Proof Generation", |b| {
        b.iter(|| {
            black_box(Proof::proof(sk, pk, &bases, &statements));
        })
    });

    let proof = Proof::proof(sk, pk, &bases, &statements);
    group.bench_function("Proof Verification", |b| {
        b.iter(|| {
            black_box(proof.verify(pk, &bases, &statements));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_encrypt_decrypt, bench_schnorr_proofs);
criterion_main!(benches);
