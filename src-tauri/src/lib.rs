use k256::{
    ecdsa::{signature::Signer, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
use pbkdf2::pbkdf2_hmac;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use zeroize::Zeroize;

// =====================================================
// Tauri Commands (called from frontend)
// =====================================================

#[tauri::command]
fn generate_key(
    layer1: String,
    layer2: String,
    layer3: String,
    layer4: String,
    layer5: String,
    quantum_shield: bool,
) -> Result<KeyOutput, String> {
    // Build recipe (same format as browser version for determinism)
    let recipe = format!(
        "L1:{}|FORTRESS|L2:{}|FORTRESS|L3:{}|FORTRESS|L4:{}|FORTRESS|L5:{}",
        layer1, layer2, layer3, layer4, layer5
    );

    // Derive private key
    let mut priv_key_bytes = derive_private_key(&recipe, quantum_shield)?;

    // Validate key is in valid secp256k1 range
    let secret_key = SecretKey::from_slice(&priv_key_bytes)
        .map_err(|_| "Generated key is outside valid range. Modify your recipe slightly.".to_string())?;

    let signing_key = SigningKey::from(&secret_key);
    let verifying_key = VerifyingKey::from(&signing_key);

    // Get public keys
    let pub_point = verifying_key.to_encoded_point(false); // uncompressed
    let pub_point_compressed = verifying_key.to_encoded_point(true); // compressed

    let priv_hex = hex::encode(&priv_key_bytes);
    let pub_compressed_hex = hex::encode(pub_point_compressed.as_bytes());
    let pub_uncompressed_hex = hex::encode(pub_point.as_bytes());

    // Generate addresses
    let wif_btc = private_key_to_wif(&priv_key_bytes, 0x80);
    let wif_doge = private_key_to_wif(&priv_key_bytes, 0x9E);
    let btc_addr = public_key_to_address(pub_point_compressed.as_bytes(), 0x00);
    let doge_addr = public_key_to_address(pub_point_compressed.as_bytes(), 0x1E);
    let eth_addr = public_key_to_eth_address(pub_point.as_bytes());

    // Verification hash
    let verify_hash = hex::encode(Sha256::digest(&priv_key_bytes));

    // SECURE MEMORY ZEROING - key material is zeroed when done
    priv_key_bytes.zeroize();

    Ok(KeyOutput {
        priv_key_hex: priv_hex,
        wif_btc,
        wif_doge,
        btc_address: btc_addr,
        doge_address: doge_addr,
        eth_address: eth_addr,
        verify_hash,
        pub_compressed: pub_compressed_hex,
        pub_uncompressed: pub_uncompressed_hex,
    })
}

#[tauri::command]
fn run_self_test() -> Result<Vec<TestResult>, String> {
    let mut results = Vec::new();

    // Test 1: SHA-256 ("abc")
    let sha_abc = hex::encode(Sha256::digest(b"abc"));
    results.push(TestResult {
        name: "SHA-256 (\"abc\")".into(),
        passed: sha_abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        expected: "ba7816bf...".into(),
        got: sha_abc[..16].to_string() + "...",
    });

    // Test 2: SHA-256 (empty)
    let sha_empty = hex::encode(Sha256::digest(b""));
    results.push(TestResult {
        name: "SHA-256 (empty)".into(),
        passed: sha_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        expected: "e3b0c442...".into(),
        got: sha_empty[..16].to_string() + "...",
    });

    // Test 3: RIPEMD-160 ("abc")
    let ripe_abc = hex::encode(Ripemd160::digest(b"abc"));
    results.push(TestResult {
        name: "RIPEMD-160 (\"abc\")".into(),
        passed: ripe_abc == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        expected: "8eb208f7...".into(),
        got: ripe_abc[..16].to_string() + "...",
    });

    // Test 4: Keccak-256 (empty)
    let keccak_empty = hex::encode(Keccak256::digest(b""));
    results.push(TestResult {
        name: "Keccak-256 (empty)".into(),
        passed: keccak_empty == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        expected: "c5d24601...".into(),
        got: keccak_empty[..16].to_string() + "...",
    });

    // Test 5: secp256k1 pubkey (privkey=1)
    let one_bytes = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let sk = SecretKey::from_slice(&one_bytes).unwrap();
    let vk = VerifyingKey::from(SigningKey::from(&sk));
    let pub_hex = hex::encode(vk.to_encoded_point(true).as_bytes());
    results.push(TestResult {
        name: "secp256k1 pubkey (privkey=1)".into(),
        passed: pub_hex == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        expected: "0279be66...".into(),
        got: pub_hex[..16].to_string() + "...",
    });

    // Test 6: Bitcoin address (privkey=1)
    let btc_addr = public_key_to_address(vk.to_encoded_point(true).as_bytes(), 0x00);
    results.push(TestResult {
        name: "Bitcoin address (privkey=1)".into(),
        passed: btc_addr == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        expected: "1BgGZ9tc...".into(),
        got: btc_addr[..12].to_string() + "...",
    });

    // Test 7: Ethereum address (privkey=1)
    let eth_addr = public_key_to_eth_address(vk.to_encoded_point(false).as_bytes());
    results.push(TestResult {
        name: "Ethereum address (privkey=1)".into(),
        passed: eth_addr.to_lowercase() == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        expected: "0x7e5f45...".into(),
        got: eth_addr[..12].to_string() + "...",
    });

    // Test 8: WIF encoding (privkey=1)
    let wif = private_key_to_wif(&one_bytes, 0x80);
    results.push(TestResult {
        name: "WIF encoding (privkey=1)".into(),
        passed: wif == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
        expected: "KwDiBf89...".into(),
        got: wif[..12].to_string() + "...",
    });

    // Test 9: PBKDF2 determinism
    let mut d1 = [0u8; 32];
    let mut d2 = [0u8; 32];
    pbkdf2_hmac::<Sha512>(b"test-recipe", b"FortressKey-v1-deterministic-salt-2025", 1000, &mut d1);
    pbkdf2_hmac::<Sha512>(b"test-recipe", b"FortressKey-v1-deterministic-salt-2025", 1000, &mut d2);
    results.push(TestResult {
        name: "PBKDF2-SHA512 determinism".into(),
        passed: d1 == d2,
        expected: "match".into(),
        got: if d1 == d2 { "match" } else { "mismatch" }.into(),
    });

    // Test 10: Memory zeroing
    let mut secret = [0xFFu8; 32];
    secret.zeroize();
    results.push(TestResult {
        name: "Secure memory zeroing (zeroize)".into(),
        passed: secret == [0u8; 32],
        expected: "all zeros".into(),
        got: if secret == [0u8; 32] { "all zeros" } else { "NOT zeroed" }.into(),
    });

    Ok(results)
}

#[tauri::command]
fn verify_recipe(
    layer1: String,
    layer2: String,
    layer3: String,
    layer4: String,
    layer5: String,
    quantum_shield: bool,
    expected_hash: String,
) -> Result<bool, String> {
    let recipe = format!(
        "L1:{}|FORTRESS|L2:{}|FORTRESS|L3:{}|FORTRESS|L4:{}|FORTRESS|L5:{}",
        layer1, layer2, layer3, layer4, layer5
    );
    let mut priv_key_bytes = derive_private_key(&recipe, quantum_shield)?;
    let hash = hex::encode(Sha256::digest(&priv_key_bytes));
    priv_key_bytes.zeroize();
    Ok(hash == expected_hash)
}

// =====================================================
// Internal crypto functions
// =====================================================

fn derive_private_key(recipe: &str, quantum_shield: bool) -> Result<Vec<u8>, String> {
    let salt = b"FortressKey-v1-deterministic-salt-2025";
    let mut key_bytes = vec![0u8; 32];

    // Step 1: PBKDF2-SHA512 (500,000 rounds)
    pbkdf2_hmac::<Sha512>(recipe.as_bytes(), salt, 500_000, &mut key_bytes);

    // Step 2: Quantum Shield
    if quantum_shield {
        // Keccak-256 cascade (10,000 rounds)
        for _ in 0..10_000 {
            let hash = Keccak256::digest(&key_bytes);
            key_bytes.copy_from_slice(&hash);
        }

        // SHA-256 + Keccak-256 XOR fusion
        let sha_result = Sha256::digest(&key_bytes);
        let keccak_result = Keccak256::digest(&key_bytes);
        for i in 0..32 {
            key_bytes[i] = sha_result[i] ^ keccak_result[i];
        }
    }

    Ok(key_bytes)
}

fn private_key_to_wif(priv_key: &[u8], network_byte: u8) -> String {
    let mut extended = Vec::with_capacity(34);
    extended.push(network_byte);
    extended.extend_from_slice(priv_key);
    extended.push(0x01); // compressed flag

    let checksum = &Sha256::digest(&Sha256::digest(&extended))[..4];
    extended.extend_from_slice(checksum);

    bs58::encode(&extended).into_string()
}

fn public_key_to_address(compressed_pubkey: &[u8], version_byte: u8) -> String {
    let sha = Sha256::digest(compressed_pubkey);
    let ripe = Ripemd160::digest(&sha);

    let mut versioned = Vec::with_capacity(21);
    versioned.push(version_byte);
    versioned.extend_from_slice(&ripe);

    let checksum = &Sha256::digest(&Sha256::digest(&versioned))[..4];
    versioned.extend_from_slice(checksum);

    bs58::encode(&versioned).into_string()
}

fn public_key_to_eth_address(uncompressed_pubkey: &[u8]) -> String {
    // Skip the 04 prefix byte
    let pub_bytes = &uncompressed_pubkey[1..];
    let hash = Keccak256::digest(pub_bytes);
    // Last 20 bytes
    format!("0x{}", hex::encode(&hash[12..]))
}

// =====================================================
// Data structures
// =====================================================

#[derive(serde::Serialize)]
struct KeyOutput {
    priv_key_hex: String,
    wif_btc: String,
    wif_doge: String,
    btc_address: String,
    doge_address: String,
    eth_address: String,
    verify_hash: String,
    pub_compressed: String,
    pub_uncompressed: String,
}

#[derive(serde::Serialize)]
struct TestResult {
    name: String,
    passed: bool,
    expected: String,
    got: String,
}

// =====================================================
// App entry point
// =====================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            generate_key,
            run_self_test,
            verify_recipe,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
