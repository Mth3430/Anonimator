//! L'anonymiseur appliqué à du vrai code : celui de ce dépôt.

use anonimator::anon::Anonymizer;
use anonimator::vault::Vault;
use anonimator::workspace::Workspace;
use std::path::Path;

#[test]
fn every_file_of_this_repo_round_trips_and_passes_the_audit() {
    let ws = Workspace::open(Path::new(env!("CARGO_MANIFEST_DIR")), false).unwrap();
    let mut anon = Anonymizer::new(Vault::default());
    ws.prepare(&mut anon);
    let files = ws.shareable_files();
    assert!(files.len() >= 10, "{files:?}");
    for path in files {
        let masked = ws
            .read_anonymized(&path, &mut anon)
            .unwrap_or_else(|e| panic!("{path} : {e:#}"));
        assert_eq!(
            anon.restore(&masked),
            ws.read_real(&path).unwrap(),
            "{path}"
        );
        let findings = anon.audit(&masked);
        assert!(findings.is_empty(), "{path} : {findings:?}");
    }
}

#[test]
fn project_specific_names_are_hidden_in_real_code() {
    let ws = Workspace::open(Path::new(env!("CARGO_MANIFEST_DIR")), false).unwrap();
    let mut anon = Anonymizer::new(Vault::default());
    ws.prepare(&mut anon);
    let masked = ws.read_anonymized("src/vault.rs", &mut anon).unwrap();
    for name in [
        "random_suffix",
        "new_token",
        "class_of",
        "Vault",
        "reverse",
        "SUFFIX_LEN",
    ] {
        assert!(!masked.contains(name), "{name} visible :\n{masked}");
    }
    for public in ["HashMap", "impl", "serde", "std::collections"] {
        assert!(masked.contains(public), "{public} a disparu :\n{masked}");
    }
    let local = ws.read_anonymized("src/local.rs", &mut anon).unwrap();
    for public in [
        "Duration",
        "Value",
        "ureq::",
        "anyhow",
        "Deserialize",
        "from_secs",
    ] {
        assert!(local.contains(public), "{public} a disparu :\n{local}");
    }
    assert!(
        !local.contains("LocalAi") && !local.contains("parse_plan"),
        "{local}"
    );
}
