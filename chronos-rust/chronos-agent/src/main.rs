use chronos_core::memory::SecureString;
use chronos_core::tamper::AntiTamper;
use chronos_crypto::fhe::{FheEngine, PrototypeFhe};
use chronos_crypto::snark::{NizkProver, SchnorrNizk};
use chronos_crypto::vdf::{VdfEngine, WesolowskiVdf};
use chronos_net::drand::DrandClient;
use num_bigint::BigUint;
use num_traits::Num;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== CHRONOS RUST AGENT BOOTSTRAP ===");

    // Step 1: Fetch external randomness as the mission seed.
    println!("[1/5] Fetching Drand randomness beacon...");
    let drand = DrandClient::new("https://api.drand.sh");
    let beacon = drand.fetch_latest().await.unwrap_or_else(|_| {
        eprintln!("[WARN] Drand unreachable. Using local fallback seed.");
        chronos_net::drand::DrandBeacon {
            round: 0,
            randomness: "deadbeef00000000000000000000000000000000000000000000000000000000"
                .to_string(),
            signature: String::new(),
        }
    });
    println!("      Beacon round: {}", beacon.round);

    // Step 2: Key generation and secure memory.
    println!("[2/5] Generating Paillier FHE keypair, pinning secret key to secure memory...");
    let fhe = PrototypeFhe;
    let keypair = fhe.keygen();
    // secret_bytes() now returns the 32-byte entropy seed for the Schnorr NIZK
    let sk_bytes = keypair.secret_bytes();
    
    // Create the secure memory wrapper BEFORE executing the mission
    let _secure_sk = SecureString::new(sk_bytes.clone());
    println!("      Keypair pinned in SecureString. Additive Homomorphism ready.");

    // Step 3: Spawn VDF time-lock on a dedicated blocking thread.
    // We use a hardcoded 1024-bit RSA modulus for the Wesolowski VDF prototype.
    let vdf_n_hex = "\
        c4b36f86b7188b1f4df4f661df2c70c1e847cd3b9b4625b5969542a27fc7e8a9\
        155ebc402175c5e89d1b09b0b46321b19901f468249fc21370211ff1a134a65b\
        308a3d5f992a5d7c30f40a1b8e622b7a421b332b5dc98a2806b0b2b801a6b0c2\
        8fc07914f6b0b533f81e3a6cd2ab5f8992a54fb22b9b5f543cb6824b22b10a29";
    let vdf_n = BigUint::from_str_radix(vdf_n_hex, 16).unwrap();
    let vdf_seed = beacon.randomness.as_bytes().to_vec();

    println!("[3/5] Spawning Wesolowski VDF time-lock (10k sequential squarings)...");
    let vdf_handle = tokio::task::spawn_blocking(move || {
        let vdf = WesolowskiVdf { n: vdf_n };
        vdf.evaluate(&vdf_seed, 10_000)
    });

    // Step 4: Spawn AntiTamper on a dedicated OS thread — NOT from async.
    println!("[4/5] Spawning anti-tamper daemon on dedicated OS thread...");
    let (tamper_tx, tamper_rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        let mut tamper = AntiTamper::new(500);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if tamper.tick() {
                let _ = tamper_tx.send(true);
                break;
            }
        }
    });

    // Execute mission under FHE using beacon randomness as inputs.
    let beacon_bytes = beacon.randomness.as_bytes();
    let m1 = (beacon_bytes[0] as u64 % 50) + 2; 
    let m2 = (beacon_bytes[1] as u64 % 50) + 2;
    let c1 = fhe.encrypt(&keypair, m1);
    let c2 = fhe.encrypt(&keypair, m2);
    
    // Homomorphic ADDITION (Paillier), not multiplication
    let c_sum = fhe.homomorphic_add(&keypair, &c1, &c2);
    let decrypted_sum = fhe.decrypt(&keypair, &c_sum);
    println!(
        "      E({}) + E({}) -> decrypt -> {} (expected {})",
        m1, m2, decrypted_sum, m1 + m2
    );
    
    if decrypted_sum != m1 + m2 {
        eprintln!("FATAL: Paillier FHE integrity check failed. Triggering erasure.");
        return Ok(());
    }

    if tamper_rx.try_recv().unwrap_or(false) {
        eprintln!("FATAL: Tamper detected. Triggering immediate erasure.");
        return Ok(());
    }

    sleep(Duration::from_millis(50)).await;

    // Step 5: Await VDF expiry and commit to key erasure.
    println!("[5/5] Awaiting Wesolowski VDF time-lock...");
    let proof = vdf_handle.await?;
    println!("      VDF Proof generated: pi length = {} bytes", proof.pi.len());

    // Schnorr NIZK over the key before erasure.
    println!("      Generating Schnorr NIZK proof of secret key possession...");
    let prover = SchnorrNizk;
    let mut sk_array = [0u8; 32];
    let secure_bytes = _secure_sk.as_bytes();
    let len = std::cmp::min(secure_bytes.len(), 32);
    sk_array[..len].copy_from_slice(&secure_bytes[..len]);
    
    let nizk_proof = prover.prove(&sk_array);
    let verified = prover.verify(&nizk_proof);
    println!("      Schnorr NIZK verified: {}", verified);

    println!("=== AGENT LIFECYCLE COMPLETE ===");
    // `_secure_sk` drops here -> triple-pass volatile zeroization of heap bytes.
    Ok(())
}
