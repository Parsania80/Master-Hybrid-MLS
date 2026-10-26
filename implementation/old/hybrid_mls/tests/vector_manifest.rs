use std::fs;
use std::path::PathBuf;

use sha3::{Digest, Sha3_256};

fn sha3_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn vector_manifest_sha3_matches_all_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_dir = root.join("tests").join("vectors");
    let manifest = fs::read_to_string(vectors_dir.join("MANIFEST.sha3"))
        .expect("read tests/vectors/MANIFEST.sha3");

    let mut validated = 0usize;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let expected = parts.next().expect("manifest hash");
        let filename = parts.next().expect("manifest filename");
        assert!(
            parts.next().is_none(),
            "manifest line should contain only hash and filename: {trimmed}"
        );

        let bytes = fs::read(vectors_dir.join(filename))
            .unwrap_or_else(|e| panic!("read fixture {filename}: {e}"));
        let actual = sha3_hex(&bytes);
        assert_eq!(actual, expected, "fixture hash mismatch for {filename}");
        validated += 1;
    }

    assert!(
        validated > 0,
        "manifest should validate at least one fixture"
    );
}
