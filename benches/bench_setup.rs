extern crate hildeguard;

use criterion::measurement::WallTime; // Import WallTime for the BenchmarkGroup
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use hildeguard::enrollment_record::EnrollmentRecord;
use hildeguard::ratelimiter::RateLimiter;
use hildeguard::server::Server;
use tokio::runtime::Runtime;

/// Runs the encryption benchmark for a given number of users (single run)
fn run_encryption_benchmark(group: &mut criterion::BenchmarkGroup<'_, WallTime>, num_users: usize) {
    let ratelimiter = RateLimiter::new();
    let server = Server::new(ratelimiter.public_key);
    let password = "securepassword";

    // Benchmark the encryption process for `num_users` users
    group.bench_with_input(
        BenchmarkId::new("Encrypt", num_users),
        &num_users,
        |b, &num_users| {
            b.iter_custom(|_| {
                let start = std::time::Instant::now();

                for _ in 0..num_users {
                    let (m, ns) = server.encrypt_init();
                    let (y_0, y_1, proof, nr) = ratelimiter.encrypt(ns);
                    black_box(server.encrypt_finish(password, y_0, y_1, nr, proof, ns, m));
                }

                start.elapsed()
            });
        },
    );
}

/// Criterion configuration and execution
fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encryption Benchmarks");

    // Configure the benchmark
    group
        .sample_size(10) // More samples for better accuracy
        .warm_up_time(std::time::Duration::from_secs(10)) // Warm-up phase
        .measurement_time(std::time::Duration::from_secs(60)); // Measure for 60 seconds

    run_encryption_benchmark(&mut group, 1_000_000); // Benchmark with 1 million users
    group.finish();
}

// Register benchmarks
criterion_group!(benches, bench_encryption);
criterion_main!(benches);
