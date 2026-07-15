use chronos_core::memory::SecureString;
use chronos_core::tamper::AntiTamper;
use chronos_crypto::fhe::{FheEngine, PrototypeFhe};
use chronos_crypto::snark::{ErasureCommitter, HashCommitter};
use chronos_crypto::vdf::{VdfEngine, PoswVdf};
use chronos_net::drand::DrandClient;
use sha2::{Digest, Sha256};
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
    println!("[2/5] Generating FHE keypair, pinning secret key to secure memory...");
    let fhe = PrototypeFhe;
    let keypair = fhe.keygen();
    // secret_bytes() exposes d only as raw bytes — d field itself is private.
    // Compute hash BEFORE moving bytes into SecureString so the key
    // never exists unguarded in two heap locations simultaneously.
    // NOTE: Vec<u8> stack metadata (ptr/len/cap) is not zeroized by Drop.
    // Only the heap bytes are wiped. Acceptable for this prototype.
    let sk_bytes = keypair.secret_bytes().to_vec();
    let key_hash: [u8; 32] = Sha256::digest(&sk_bytes).into();
    let _secure_sk = SecureString::new(sk_bytes);
    println!("      n={}, e={} (d pinned in SecureString)", keypair.n, keypair.e);

    // Step 3: Spawn VDF time-lock on a dedicated blocking thread.
    println!("[3/5] Spawning VDF time-lock (10M iterations)...");
    let vdf_seed = beacon.randomness.as_bytes().to_vec();
    let vdf_handle = tokio::task::spawn_blocking(move || {
        let vdf = PoswVdf;
        vdf.evaluate(&vdf_seed, 10_000_000)
    });

    // Step 4: Spawn AntiTamper on a dedicated OS thread — NOT from async.
    // Tokio scheduler jitter causes false positives when called from an async task.
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
    // Ties the computation to the external randomness — not hardcoded constants.
    let beacon_bytes = beacon.randomness.as_bytes();
    let m1 = (beacon_bytes[0] as u64 % 50) + 2; // range 2..51, always < n=3233
    let m2 = (beacon_bytes[1] as u64 % 50) + 2;
    let c1 = fhe.encrypt(&keypair, m1);
    let c2 = fhe.encrypt(&keypair, m2);
    let c_product = fhe.homomorphic_mul(&keypair, c1, c2);
    let decrypted_product = fhe.decrypt(&keypair, c_product);
    println!(
        "      E({}) * E({}) -> decrypt -> {} (expected {})",
        m1, m2, decrypted_product, m1 * m2
    );
    // BUG 1 FIX: controlled return instead of assert_eq! (panic bypasses clean Drop
    // on some unwind configurations, leaving key in memory).
    if decrypted_product != m1 * m2 {
        eprintln!("FATAL: FHE integrity check failed. Triggering erasure.");
        return Ok(());
    }

    // Check tamper signal (non-blocking poll).
    if tamper_rx.try_recv().unwrap_or(false) {
        eprintln!("FATAL: Tamper detected. Triggering immediate erasure.");
        return Ok(());
    }

    sleep(Duration::from_millis(50)).await;

    // Step 5: Await VDF expiry and commit to key erasure.
    println!("[5/5] Awaiting VDF time-lock...");
    let vdf_output = vdf_handle.await?;
    println!("      VDF output length: {} bytes", vdf_output.len());

    // Hash commitment over the key before erasure.
    // See snark.rs for honest description of what this proves.
    let committer = HashCommitter;
    let commitment = committer.commit(_secure_sk.as_bytes());
    let verified = committer.verify(&key_hash, &commitment);
    println!("      Erasure commitment verified: {}", verified);

    println!("=== AGENT LIFECYCLE COMPLETE ===");
    // `_secure_sk` drops here -> triple-pass volatile zeroization of heap bytes.
    Ok(())
}
