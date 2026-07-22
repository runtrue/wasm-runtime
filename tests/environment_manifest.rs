//! Environment manifest identity and validation integration tests.

use runtrue_wasm_runtime::{
    EnvironmentArtifact, EnvironmentBuild, EnvironmentCommands, EnvironmentFilesystem,
    EnvironmentLanguage, EnvironmentManifest, Error,
};
use serde_json::{Value, json};

fn valid_manifest() -> EnvironmentManifest {
    EnvironmentManifest {
        schema_version: 1,
        environment_id: String::new(),
        execution_profile: "wasix32-v1".to_owned(),
        language: EnvironmentLanguage {
            name: "rust".to_owned(),
            version: "1.94.0".to_owned(),
            implementation: "rustc".to_owned(),
        },
        artifact: EnvironmentArtifact {
            format: "webc".to_owned(),
            path: "environment.webc".to_owned(),
            sha256: "11".repeat(32),
        },
        required_wasm_features: vec!["bulk-memory".to_owned(), "simd128".to_owned()],
        commands: EnvironmentCommands {
            default: "main".to_owned(),
            available: vec!["health".to_owned(), "main".to_owned()],
        },
        filesystem: EnvironmentFilesystem {
            immutable: vec!["/bin".to_owned(), "/usr/lib".to_owned()],
            writable: vec!["/tmp".to_owned(), "/work".to_owned()],
        },
        build: EnvironmentBuild {
            toolchain_id: "wasix-rust-1.94.0".to_owned(),
            source_digest: format!("sha256:{}", "22".repeat(32)),
            lock_digest: format!("sha256:{}", "33".repeat(32)),
        },
    }
    .with_calculated_environment_id()
    .expect("valid fixture")
}

#[test]
fn parses_a_valid_manifest_and_has_a_stable_golden_identity() {
    let manifest = valid_manifest();
    assert_eq!(
        manifest.environment_id,
        "sha256:e3c767685c231a3e709285b925a234f13303f8736e1684fda2fe2cfb71b1dc83"
    );

    let encoded = serde_json::to_vec(&manifest).expect("encode manifest");
    assert_eq!(EnvironmentManifest::from_json(&encoded).unwrap(), manifest);
}

#[test]
fn json_representation_does_not_change_identity() {
    let manifest = valid_manifest();
    let reordered = json!({
        "build": {
            "lockDigest": manifest.build.lock_digest,
            "sourceDigest": manifest.build.source_digest,
            "toolchainId": manifest.build.toolchain_id,
        },
        "filesystem": manifest.filesystem,
        "commands": manifest.commands,
        "requiredWasmFeatures": manifest.required_wasm_features,
        "artifact": manifest.artifact,
        "language": manifest.language,
        "executionProfile": "wasix32-v1",
        "environmentId": manifest.environment_id,
        "schemaVersion": 1,
    });
    let pretty = serde_json::to_string_pretty(&reordered).unwrap();
    let parsed = EnvironmentManifest::from_json(pretty.as_bytes()).unwrap();
    assert_eq!(
        parsed.calculate_environment_id().unwrap(),
        parsed.environment_id
    );
}

#[test]
fn rejects_identity_tampering_and_malformed_ids() {
    let mut tampered = valid_manifest();
    tampered.language.version = "1.95.0".to_owned();
    assert!(matches!(tampered.validate(), Err(Error::Preparation(_))));

    let mut uppercase = valid_manifest();
    uppercase.environment_id = uppercase.environment_id.to_ascii_uppercase();
    assert!(matches!(uppercase.validate(), Err(Error::Preparation(_))));
}

#[test]
fn rejects_noncanonical_sets_and_command_catalogs() {
    let mut unsorted = valid_manifest();
    unsorted.required_wasm_features.reverse();
    assert!(matches!(
        unsorted.calculate_environment_id(),
        Err(Error::Preparation(_))
    ));

    let mut duplicate = valid_manifest();
    duplicate.commands.available = vec!["main".to_owned(), "main".to_owned()];
    assert!(matches!(duplicate.validate(), Err(Error::Preparation(_))));

    let mut missing_default = valid_manifest();
    missing_default.commands.default = "other".to_owned();
    assert!(matches!(
        missing_default.calculate_environment_id(),
        Err(Error::Preparation(_))
    ));
}

#[test]
fn rejects_nonportable_paths_and_writable_overlap() {
    for path in [
        "../environment.webc",
        "./environment.webc",
        "dir/environment.webc",
    ] {
        let mut manifest = valid_manifest();
        manifest.artifact.path = path.to_owned();
        assert!(matches!(
            manifest.calculate_environment_id(),
            Err(Error::Preparation(_))
        ));
    }

    let mut overlap = valid_manifest();
    overlap.filesystem.immutable.push("/work/input".to_owned());
    assert!(matches!(
        overlap.calculate_environment_id(),
        Err(Error::Preparation(_))
    ));

    let mut ancestor = valid_manifest();
    ancestor.filesystem.immutable = vec![
        "/usr".to_owned(),
        "/usr-local".to_owned(),
        "/usr/lib".to_owned(),
    ];
    assert!(matches!(
        ancestor.calculate_environment_id(),
        Err(Error::Preparation(_))
    ));
}

#[test]
fn rejects_unknown_fields_duplicate_fields_and_unsupported_schema() {
    let manifest = valid_manifest();
    let mut value = serde_json::to_value(&manifest).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("futureField".to_owned(), Value::Bool(true));
    assert!(matches!(
        EnvironmentManifest::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(Error::Preparation(_))
    ));

    let duplicate =
        serde_json::to_string(&manifest)
            .unwrap()
            .replacen('{', "{\"schemaVersion\":1,", 1);
    assert!(matches!(
        EnvironmentManifest::from_json(duplicate.as_bytes()),
        Err(Error::Preparation(_))
    ));

    let mut unsupported = manifest;
    unsupported.schema_version = 2;
    let mut unsupported_value = serde_json::to_value(&unsupported).unwrap();
    unsupported_value
        .as_object_mut()
        .unwrap()
        .insert("versionTwoField".to_owned(), Value::Bool(true));
    assert!(matches!(
        EnvironmentManifest::from_json(&serde_json::to_vec(&unsupported_value).unwrap()),
        Err(Error::UnsupportedComponent(_))
    ));
}

#[test]
fn rejects_oversized_manifests_before_json_parsing() {
    let oversized = vec![b' '; 64 * 1024 + 1];
    assert!(matches!(
        EnvironmentManifest::from_json(&oversized),
        Err(Error::Limit("environment manifest bytes"))
    ));

    let mut oversized_struct = valid_manifest();
    oversized_struct.required_wasm_features = (0..256)
        .map(|index| format!("feature-{index:03}-{}", "x".repeat(244)))
        .collect();
    assert!(matches!(
        oversized_struct.calculate_environment_id(),
        Err(Error::Limit("environment manifest bytes"))
    ));
}
