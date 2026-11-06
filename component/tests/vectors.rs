//! Published test vectors, so that this is checked against the standards and not against itself.

use hex::{decode, encode};
use medcrypto_component::core::*;

fn h(text: &str) -> Vec<u8> {
    decode(text).unwrap()
}

#[test]
fn sha256_from_fips_180() {
    assert_eq!(
        encode(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        encode(sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hkdf_from_rfc_5869() {
    let out = hkdf(
        &[0x0b; 22],
        &h("000102030405060708090a0b0c"),
        &h("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    .unwrap();
    assert_eq!(
        encode(out),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    assert_eq!(hkdf(b"k", b"s", b"i", 8160).unwrap().len(), 8160);
    assert_eq!(hkdf(b"k", b"s", b"i", 8161), Err(Error::BadOutputLength));
    assert_eq!(
        hkdf(b"k", b"s", b"i", u32::MAX),
        Err(Error::BadOutputLength)
    );
    assert_eq!(hkdf(b"k", b"s", b"i", 0).unwrap().len(), 0);
}

#[test]
fn aes_gcm_from_the_nist_vectors() {
    let (key, nonce) = ([0u8; 32], [0u8; 12]);
    assert_eq!(
        encode(seal(&key, &nonce, b"", b"").unwrap()),
        "530f8afbc74536b9a963b4f1c4cb738b"
    );
    let sealed = seal(&key, &nonce, b"", &[0u8; 16]).unwrap();
    assert_eq!(
        encode(&sealed),
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
    );
    assert_eq!(open(&key, &nonce, b"", &sealed).unwrap(), [0u8; 16]);
}

#[test]
fn any_change_to_a_sealed_message_is_refused() {
    let (key, nonce) = ([7u8; 32], [9u8; 12]);
    let sealed = seal(&key, &nonce, b"patient-17", b"hemoglobin 13.2").unwrap();
    assert_eq!(
        open(&key, &nonce, b"patient-17", &sealed).unwrap(),
        b"hemoglobin 13.2"
    );
    for i in 0..sealed.len() {
        let mut damaged = sealed.clone();
        damaged[i] ^= 1;
        assert_eq!(
            open(&key, &nonce, b"patient-17", &damaged),
            Err(Error::AuthenticationFailed),
            "byte {i}"
        );
    }
    assert_eq!(
        open(&key, &nonce, b"patient-18", &sealed),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        open(&[8u8; 32], &nonce, b"patient-17", &sealed),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        open(&key, &[8u8; 12], b"patient-17", &sealed),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        open(&key, &nonce, b"patient-17", &sealed[..sealed.len() - 1]),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        open(&key, &nonce, b"", b""),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn wrong_lengths_are_refused() {
    for key_length in [0, 16, 31, 33] {
        assert_eq!(
            seal(&vec![0; key_length], &[0; 12], b"", b""),
            Err(Error::BadLength)
        );
    }
    for nonce_length in [0, 8, 11, 13, 16] {
        assert_eq!(
            seal(&[0; 32], &vec![0; nonce_length], b"", b""),
            Err(Error::BadLength)
        );
        assert_eq!(
            open(&[0; 32], &vec![0; nonce_length], b"", b""),
            Err(Error::BadLength)
        );
    }
    assert_eq!(keypair_from_seed(&[0; 31]), Err(Error::BadLength));
    assert_eq!(
        keypair_from_seed(&[0; 32]),
        Err(Error::WeakSeed),
        "this must be an error, and not a trap"
    );
    assert_eq!(sign(&[0; 63], b""), Err(Error::BadLength));
    assert!(!verify(&[0; 31], b"", &[0; 64]));
    assert!(!verify(&[0; 32], b"", &[0; 63]));
}

#[test]
fn ed25519_from_rfc_8032() {
    let seed = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let (public, secret) = keypair_from_seed(&seed).unwrap();
    assert_eq!(
        encode(&public),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let signature = sign(&secret, b"").unwrap();
    assert_eq!(
        encode(&signature),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    assert!(verify(&public, b"", &signature));
    let seed = h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let (public, secret) = keypair_from_seed(&seed).unwrap();
    let signature = sign(&secret, &[0x72]).unwrap();
    assert_eq!(
        encode(&signature),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    assert!(verify(&public, &[0x72], &signature));
}

#[test]
fn a_changed_signature_or_message_does_not_verify() {
    let (public, secret) = keypair_from_seed(&[3; 32]).unwrap();
    let signature = sign(&secret, b"consent granted").unwrap();
    assert!(verify(&public, b"consent granted", &signature));
    assert!(!verify(&public, b"consent revoked", &signature));
    for i in 0..signature.len() {
        let mut damaged = signature.clone();
        damaged[i] ^= 0x10;
        assert!(!verify(&public, b"consent granted", &damaged), "byte {i}");
    }
    let (other, _) = keypair_from_seed(&[4; 32]).unwrap();
    assert!(!verify(&other, b"consent granted", &signature));
}

#[test]
fn merkle_roots_from_rfc_6962() {
    // These leaves and roots are the Certificate Transparency reference test data.
    let leaves: Vec<Vec<u8>> = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ]
    .iter()
    .map(|l| h(l))
    .collect();
    let roots = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    for (count, root) in roots.iter().enumerate() {
        assert_eq!(
            encode(merkle_root(&leaves[..=count])),
            *root,
            "{} leaves",
            count + 1
        );
    }
    assert_eq!(
        encode(merkle_root(&[])),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn a_node_cannot_pass_as_a_leaf() {
    let (a, b) = (b"a".to_vec(), b"b".to_vec());
    let root = merkle_root(&[a.clone(), b.clone()]);
    // The concatenation of the leaf hashes, as a single leaf, has to give a different root.
    let joined = [
        sha256(&[&[0u8][..], &a].concat()),
        sha256(&[&[0u8][..], &b].concat()),
    ]
    .concat();
    assert_ne!(merkle_root(&[joined]), root);
    assert_ne!(merkle_root(&[b.clone(), a.clone()]), root, "order matters");
}

#[test]
fn audit_links_depend_on_every_part_and_the_boundary_between_them() {
    let base = audit_link(b"ab", b"c");
    assert_ne!(
        audit_link(b"a", b"bc"),
        base,
        "moving bytes across the boundary has to change it"
    );
    assert_ne!(audit_link(b"ab", b"d"), base);
    assert_ne!(audit_link(b"ax", b"c"), base);
    assert_eq!(audit_link(b"ab", b"c"), base);
    assert_eq!(base.len(), 32);
}

#[test]
fn constant_time_comparison_gives_the_right_answers() {
    assert!(constant_time_equal(b"same", b"same"));
    assert!(constant_time_equal(b"", b""));
    assert!(!constant_time_equal(b"same", b"sane"));
    assert!(!constant_time_equal(b"same", b"same "));
}

/// Every host has to print exactly this file, so the file itself is checked here against native code.
#[test]
fn the_expected_host_output_is_what_the_cryptography_gives() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let sealed = seal(&key, &nonce, b"", &[0u8; 16]).unwrap();
    let mut tampered = sealed.clone();
    tampered[0] ^= 1;
    assert_eq!(
        open(&key, &nonce, b"", &tampered),
        Err(Error::AuthenticationFailed)
    );
    let seed = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let (public, secret) = keypair_from_seed(&seed).unwrap();
    let signature = sign(&secret, b"").unwrap();
    let leaves = [h(""), h("00"), h("10")];
    let expected = [
        format!("sha256 {}", encode(sha256(b"abc"))),
        format!(
            "hkdf {}",
            encode(
                hkdf(
                    &[0x0b; 22],
                    &h("000102030405060708090a0b0c"),
                    &h("f0f1f2f3f4f5f6f7f8f9"),
                    42
                )
                .unwrap()
            )
        ),
        format!("seal {}", encode(&sealed)),
        format!("open {}", encode(open(&key, &nonce, b"", &sealed).unwrap())),
        "open-tampered authentication-failed".to_string(),
        "seal-short-key bad-length".to_string(),
        format!("public-key {}", encode(&public)),
        format!("signature {}", encode(&signature)),
        format!("verify {}", verify(&public, b"", &signature)),
        format!("verify-wrong-message {}", verify(&public, b"x", &signature)),
        format!("merkle-root {}", encode(merkle_root(&leaves))),
        format!("audit-link {}", encode(audit_link(b"ab", b"c"))),
        format!(
            "constant-time-equal {} {}",
            constant_time_equal(b"a", b"a"),
            constant_time_equal(b"a", b"b")
        ),
    ];
    let file = include_str!("../hosts/expected.txt");
    assert_eq!(
        file.lines().collect::<Vec<_>>(),
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
}
