#![forbid(unsafe_code)]

//! Standalone timing smoke benchmark for the educational mKyber reference.
//!
//! This binary is deliberately small and dependency-free. It is not a
//! statistically rigorous benchmark harness, a security evaluation, or a
//! production-performance claim. It prints no keys, entropy, or shared
//! secrets; only public component-byte measurements and timing aggregates.

use std::time::{Duration, Instant};

use mkyber::{
    EducationalMkyber512Reference, MkyberDomain, MkyberError, MultiRecipientKem, RecipientId,
    RecipientPublicKey, RecipientSet,
};

const RECIPIENT_COUNT: usize = 2;
const WARMUP_ITERATIONS: usize = 2;
const SAMPLE_ITERATIONS: usize = 5;
const BENCHMARK_DOMAIN: MkyberDomain = MkyberDomain::new([0x42; 32]);

fn main() -> Result<(), MkyberError> {
    let backend = EducationalMkyber512Reference;

    for _ in 0..WARMUP_ITERATIONS {
        drop(backend.keygen_with_os_rng(BENCHMARK_DOMAIN)?);
    }
    let keygen_total = measure(SAMPLE_ITERATIONS, || {
        backend.keygen_with_os_rng(BENCHMARK_DOMAIN)
    })?;

    let mut key_pairs = Vec::with_capacity(RECIPIENT_COUNT);
    let mut public_recipients = Vec::with_capacity(RECIPIENT_COUNT);
    for index in 0..RECIPIENT_COUNT {
        let key_pair = backend.keygen_with_os_rng(BENCHMARK_DOMAIN)?;
        public_recipients.push(RecipientPublicKey {
            recipient: RecipientId::new((index + 1) as u32),
            key: key_pair.public_key().clone(),
        });
        key_pairs.push(key_pair);
    }
    let recipients = RecipientSet::new(BENCHMARK_DOMAIN, public_recipients)?;

    for _ in 0..WARMUP_ITERATIONS {
        drop(backend.encapsulate_with_os_rng(&recipients)?);
    }
    let encapsulation_total = measure(SAMPLE_ITERATIONS, || {
        backend.encapsulate_with_os_rng(&recipients)
    })?;

    let benchmark_ciphertext = backend.encapsulate_with_os_rng(&recipients)?;
    let component_costs = benchmark_ciphertext.ciphertext.measured_component_costs();
    for _ in 0..WARMUP_ITERATIONS {
        decapsulate_for_all(&backend, &key_pairs, &benchmark_ciphertext)?;
    }
    let mut decapsulation_total = Duration::ZERO;
    for _ in 0..SAMPLE_ITERATIONS {
        let started = Instant::now();
        decapsulate_for_all(&backend, &key_pairs, &benchmark_ciphertext)?;
        decapsulation_total += started.elapsed();
    }

    println!("profile={}", EducationalMkyber512Reference::PROFILE_LABEL);
    println!("implementation=EducationalMkyber512Reference");
    println!("parameter_set=q3329_n256_k2_eta1_3_eta2_2_du11_dv3_message16");
    println!("purpose=educational_thesis_reference_only");
    println!("recipient_count={RECIPIENT_COUNT}");
    println!(
        "common_component_measured_bytes={}",
        component_costs.common_component().measured_bytes()
    );
    println!(
        "recipient_component_total_measured_bytes={}",
        component_costs.recipient_component_total().measured_bytes()
    );
    println!(
        "total_component_measured_bytes={}",
        component_costs.total_component().measured_bytes()
    );
    println!("warmup_iterations={WARMUP_ITERATIONS}");
    println!("sample_iterations={SAMPLE_ITERATIONS}");
    println!(
        "keygen_average_ns={}",
        average_nanoseconds(keygen_total, SAMPLE_ITERATIONS)
    );
    println!(
        "encapsulation_average_ns={}",
        average_nanoseconds(encapsulation_total, SAMPLE_ITERATIONS)
    );
    println!(
        "decapsulation_per_recipient_average_ns={}",
        average_nanoseconds(decapsulation_total, SAMPLE_ITERATIONS * RECIPIENT_COUNT)
    );
    println!("timing_scope=release_build_instant_elapsed_environment_dependent");
    println!("security_claim=none");

    Ok(())
}

fn measure<T>(
    iterations: usize,
    mut operation: impl FnMut() -> Result<T, MkyberError>,
) -> Result<Duration, MkyberError> {
    let mut total = Duration::ZERO;
    for _ in 0..iterations {
        let started = Instant::now();
        drop(operation()?);
        total += started.elapsed();
    }
    Ok(total)
}

fn decapsulate_for_all(
    backend: &EducationalMkyber512Reference,
    key_pairs: &[mkyber::MkyberKeyPair],
    encapsulation: &mkyber::MkyberEncapsulation,
) -> Result<(), MkyberError> {
    for (index, key_pair) in key_pairs.iter().enumerate() {
        drop(backend.decapsulate(
            key_pair.private_key(),
            &encapsulation.ciphertext,
            RecipientId::new((index + 1) as u32),
        )?);
    }
    Ok(())
}

fn average_nanoseconds(total: Duration, operations: usize) -> u128 {
    total.as_nanos() / operations as u128
}
