extern crate hildeguard;

use criterion::measurement::WallTime; // Import WallTime for the BenchmarkGroup
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use hildeguard::enrollment_record::EnrollmentRecord;
use hildeguard::ratelimiter::RateLimiter;
use hildeguard::server::Server;
use tokio::runtime::Runtime;

/// Runs the opt-out benchmark for a given number of records (single run)
fn run_opt_out_benchmark(group: &mut criterion::BenchmarkGroup<'_, WallTime>, num_records: usize) {
    let runtime = Runtime::new().unwrap();
    let ratelimiter = RateLimiter::new();
    let server = Server::new(ratelimiter.public_key);
    let password = "securepassword";

    // Generate & store `num_records` enrollment records
    let records: Vec<EnrollmentRecord> = (0..num_records)
        .map(|_| {
            let (m, ns) = server.encrypt_init();
            let (y_0, y_1, proof, nr) = ratelimiter.encrypt(ns);
            server.encrypt_finish(password, y_0, y_1, nr, proof, ns, m)
        })
        .collect();

    runtime.block_on(async {
        for record in &records {
            server.store_enrollment_record(record.clone()).await;
        }
    });

    // Run the opt-out benchmark only **once**
    group.bench_with_input(
        BenchmarkId::new("Opt-Out", num_records),
        &records,
        |b, records| {
            b.iter_custom(|_| {
                let start = std::time::Instant::now();
                for record in records {
                    black_box(server.opt_out(ratelimiter.secret_key, record));
                }
                start.elapsed()
            });
        },
    );
}

/// Criterion configuration and execution
fn bench_opt_out(c: &mut Criterion) {
    let mut group = c.benchmark_group("Opt-Out Benchmarks");

    // Configure a single run
    group
        .sample_size(10) // Run only once
        .warm_up_time(std::time::Duration::from_secs(60)) // No warm-up
        .measurement_time(std::time::Duration::from_secs(100)); // Fastest possible measurement

    run_opt_out_benchmark(&mut group, 1000_000); // Test with num records
    group.finish();
}

// Register benchmarks
criterion_group!(benches, bench_opt_out);
criterion_main!(benches);
