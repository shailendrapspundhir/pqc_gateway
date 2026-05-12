use anyhow::Result;
use clap::{Parser, Subcommand};
use pqc_tls::certgen::{
    CaParams, CertAlgorithm, ServerCertParams,
    generate_ca, generate_self_signed_server, generate_server_cert,
};
use pqc_tls::fips;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pqc-certgen", about = "PQC Gateway Certificate Generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a complete CA + server certificate set for the gateway.
    Generate {
        /// Output directory for certificate files.
        #[arg(short, long, default_value = "config/certs")]
        output: PathBuf,

        /// Signature algorithm: ecdsa-p256 or ed25519.
        #[arg(short, long, default_value = "ecdsa-p256")]
        algorithm: String,

        /// Server common name.
        #[arg(long, default_value = "localhost")]
        cn: String,

        /// DNS Subject Alternative Names (comma-separated).
        #[arg(long, default_value = "localhost")]
        san_dns: String,

        /// IP Subject Alternative Names (comma-separated).
        #[arg(long, default_value = "127.0.0.1,::1")]
        san_ips: String,

        /// Certificate validity in days.
        #[arg(long, default_value = "365")]
        days: u32,
    },

    /// Generate a self-signed server certificate (quick testing).
    SelfSigned {
        #[arg(short, long, default_value = "config/certs")]
        output: PathBuf,

        #[arg(short, long, default_value = "ecdsa-p256")]
        algorithm: String,

        #[arg(long, default_value = "localhost")]
        cn: String,

        #[arg(long, default_value = "localhost")]
        san_dns: String,

        #[arg(long, default_value = "127.0.0.1,::1")]
        san_ips: String,

        #[arg(long, default_value = "365")]
        days: u32,
    },

    /// Run PQC key generation demo (ML-DSA-65 + ML-KEM-768).
    PqcDemo,

    /// Run FIPS compliance checks and print report.
    FipsCheck,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            output,
            algorithm,
            cn,
            san_dns,
            san_ips,
            days,
        } => {
            let alg = parse_algorithm(&algorithm)?;
            let san_dns_list = parse_csv(&san_dns);
            let san_ip_list = parse_ips(&san_ips)?;

            std::fs::create_dir_all(&output)?;

            // Generate CA
            let ca_params = CaParams {
                algorithm: alg,
                common_name: format!("PQC Gateway CA ({algorithm})"),
                organization: "PQC Gateway".to_string(),
                validity_days: days * 2,
            };
            let (ca_generated, ca_cert) = generate_ca(&ca_params)?;
            ca_generated.write_to_files(
                &output.join("ca.crt"),
                &output.join("ca.key"),
            )?;
            println!("CA certificate:     {}", output.join("ca.crt").display());
            println!("CA private key:     {}", output.join("ca.key").display());

            // Generate server cert signed by CA
            let server_params = ServerCertParams {
                algorithm: alg,
                common_name: cn,
                san_dns: san_dns_list,
                san_ips: san_ip_list,
                organization: "PQC Gateway".to_string(),
                validity_days: days,
            };
            let server_cert = generate_server_cert(
                &server_params,
                &ca_cert,
                &ca_generated.key_pem,
            )?;
            server_cert.write_to_files(
                &output.join("server.crt"),
                &output.join("server.key"),
            )?;
            println!("Server certificate: {}", output.join("server.crt").display());
            println!("Server private key: {}", output.join("server.key").display());
            println!("\nCertificates generated with algorithm: {algorithm}");
            println!("These certs work with TLS 1.3 + PQC hybrid key exchange (X25519+ML-KEM-768).");
        }

        Commands::SelfSigned {
            output,
            algorithm,
            cn,
            san_dns,
            san_ips,
            days,
        } => {
            let alg = parse_algorithm(&algorithm)?;
            let san_dns_list = parse_csv(&san_dns);
            let san_ip_list = parse_ips(&san_ips)?;

            std::fs::create_dir_all(&output)?;

            let params = ServerCertParams {
                algorithm: alg,
                common_name: cn,
                san_dns: san_dns_list,
                san_ips: san_ip_list,
                organization: "PQC Gateway".to_string(),
                validity_days: days,
            };
            let cert = generate_self_signed_server(&params)?;
            cert.write_to_files(
                &output.join("server.crt"),
                &output.join("server.key"),
            )?;
            println!("Self-signed server certificate: {}", output.join("server.crt").display());
            println!("Server private key:             {}", output.join("server.key").display());
        }

        Commands::PqcDemo => {
            run_pqc_demo()?;
        }

        Commands::FipsCheck => {
            run_fips_check();
        }
    }

    Ok(())
}

fn run_pqc_demo() -> Result<()> {
    use pqc_tls::certgen::pqc;

    println!("=== PQC Key Generation Demo ===\n");

    // ML-DSA-65 (FIPS 204)
    println!("--- ML-DSA-65 (FIPS 204 — Digital Signatures) ---");
    let dsa_kp = pqc::generate_ml_dsa_keypair();
    println!("  Public key:  {} bytes", dsa_kp.public_key.len());
    println!("  Seed:        {} bytes", dsa_kp.seed.len());
    println!(
        "  Fingerprint: {}",
        pqc::key_fingerprint(&dsa_kp.public_key)
    );

    let message = b"Post-Quantum Cryptography Gateway - FIPS 204 test";
    let sig = pqc::ml_dsa_sign(&dsa_kp.seed, message)?;
    println!("  Signature:   {} bytes", sig.len());
    let valid = pqc::ml_dsa_verify(&dsa_kp.public_key, message, &sig)?;
    println!("  Verified:    {}\n", valid);

    // ML-KEM-768 (FIPS 203)
    println!("--- ML-KEM-768 (FIPS 203 — Key Encapsulation) ---");
    let ek_bytes = pqc::ml_kem_generate_ek_bytes();
    println!(
        "  Fingerprint: {}",
        pqc::key_fingerprint(&ek_bytes)
    );

    let result = pqc::ml_kem_full_cycle();
    println!("  Encaps key:    {} bytes", result.ek_size);
    println!("  Decaps key:    {} bytes", result.dk_size);
    println!("  Ciphertext:    {} bytes", result.ciphertext_size);
    println!("  Shared secret: {} bytes", result.shared_secret_size);
    println!("  Secrets match: {}\n", result.secrets_match);

    println!("=== PQC algorithms are operational ===");
    Ok(())
}

fn run_fips_check() {
    println!("=== FIPS Compliance Report ===\n");
    let checks = fips::run_compliance_checks(true);
    let mut all_passed = true;

    for check in &checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        let symbol = if check.passed { "✓" } else { "✗" };
        println!("  [{status}] {symbol} {} — {}", check.standard, check.description);
        println!("         {}", check.details);
        if !check.passed {
            all_passed = false;
        }
    }

    println!();
    if all_passed {
        println!("Result: ALL CHECKS PASSED");
    } else {
        println!("Result: SOME CHECKS FAILED");
        std::process::exit(1);
    }
}

fn parse_algorithm(s: &str) -> Result<CertAlgorithm> {
    match s.to_lowercase().as_str() {
        "ecdsa-p256" | "ecdsa" | "p256" => Ok(CertAlgorithm::EcdsaP256),
        "ed25519" => Ok(CertAlgorithm::Ed25519),
        other => anyhow::bail!(
            "Unknown algorithm: '{}'. Supported: ecdsa-p256, ed25519",
            other
        ),
    }
}

fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_ips(s: &str) -> Result<Vec<IpAddr>> {
    s.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpAddr>()
                .map_err(|e| anyhow::anyhow!("Invalid IP address '{}': {}", s, e))
        })
        .collect()
}