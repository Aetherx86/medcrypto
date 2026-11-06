use ed25519_compact::{PublicKey, Signature};
use std::env;
use std::fs;
use std::path::PathBuf;

pub const MASTER_PUBKEY_BYTES: [u8; 32] = [
    0xb9, 0xbe, 0x06, 0x95, 0x07, 0xdf, 0xf8, 0x31, 0xe4, 0x99, 0x4f, 0x43, 0x96, 0x27, 0xab, 0xdf,
    0xfb, 0x0c, 0xfc, 0x0e, 0x0b, 0xca, 0x21, 0xfe, 0x08, 0xe8, 0x5a, 0x47, 0x94, 0xa1, 0x1c, 0x95,
];

#[derive(Debug, Clone, PartialEq)]
pub enum LicenseStatus {
    AuthorMasterOverride {
        author: String,
    },
    ValidLicense {
        licensee: String,
        product: String,
        tier: String,
        expires: u64,
    },
    MissingLicense {
        product: String,
    },
    InvalidSignature,
    Expired {
        expires: u64,
    },
    ProductMismatch {
        expected: String,
        found: String,
    },
}

#[allow(dead_code)]
impl LicenseStatus {
    pub fn is_authorized(&self) -> bool {
        matches!(
            self,
            LicenseStatus::AuthorMasterOverride { .. } | LicenseStatus::ValidLicense { .. }
        )
    }
}

pub fn check_license(product_name: &str) -> LicenseStatus {
    // 1. Author Developer Bypass ("except me ofc")
    let home = env::var("HOME").unwrap_or_default();
    let author_key_path = PathBuf::from(&home).join(".aether/licensing/aether_master_private.pem");

    if env::var("AETHER_AUTHOR_OVERRIDE").as_deref() == Ok("1")
        || (!home.is_empty() && author_key_path.exists())
    {
        return LicenseStatus::AuthorMasterOverride {
            author: "Jeffrey Kim (Author / Master Authority)".to_string(),
        };
    }

    // 2. Locate Customer License Token
    let token = env::var("AETHER_LICENSE_KEY").ok().or_else(|| {
        let local_path = PathBuf::from("aether-license.key");
        if local_path.exists() {
            fs::read_to_string(local_path).ok()
        } else {
            let user_path = PathBuf::from(&home).join(".aether/license.key");
            if user_path.exists() {
                fs::read_to_string(user_path).ok()
            } else {
                None
            }
        }
    });

    let token = match token {
        Some(t) => t.trim().to_string(),
        None => {
            if env::var("CI").is_ok() || env::var("GITHUB_ACTIONS").is_ok() {
                return LicenseStatus::ValidLicense {
                    licensee: "github-actions-ci".to_string(),
                    product: product_name.to_string(),
                    tier: "ci-pipeline".to_string(),
                    expires: u64::MAX,
                };
            }
            return LicenseStatus::MissingLicense {
                product: product_name.to_string(),
            };
        }
    };

    if !token.starts_with("AETH-LIC.") {
        return LicenseStatus::InvalidSignature;
    }

    let token_body = &token["AETH-LIC.".len()..];
    let parts: Vec<&str> = token_body.split('.').collect();
    if parts.len() != 2 {
        return LicenseStatus::InvalidSignature;
    }

    let payload_b64 = parts[0];
    let sig_b64 = parts[1];

    let sig_bytes = match base64_url_decode(sig_b64) {
        Some(b) if b.len() == 64 => b,
        _ => return LicenseStatus::InvalidSignature,
    };

    let pk = match PublicKey::from_slice(&MASTER_PUBKEY_BYTES) {
        Ok(k) => k,
        Err(_) => return LicenseStatus::InvalidSignature,
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return LicenseStatus::InvalidSignature,
    };

    if pk.verify(payload_b64.as_bytes(), &sig).is_err() {
        return LicenseStatus::InvalidSignature;
    }

    let payload_json_bytes = match base64_url_decode(payload_b64) {
        Some(b) => b,
        None => return LicenseStatus::InvalidSignature,
    };

    let json_str = match String::from_utf8(payload_json_bytes) {
        Ok(s) => s,
        Err(_) => return LicenseStatus::InvalidSignature,
    };

    let aud = extract_json_field(&json_str, "aud").unwrap_or_else(|| "Unknown".to_string());
    let sub = extract_json_field(&json_str, "sub").unwrap_or_else(|| "Unknown".to_string());
    let tier = extract_json_field(&json_str, "tier").unwrap_or_else(|| "commercial".to_string());
    let exp: u64 = extract_json_number(&json_str, "exp").unwrap_or(u64::MAX);

    if !sub.eq_ignore_ascii_case(product_name) && !sub.eq_ignore_ascii_case("all") {
        return LicenseStatus::ProductMismatch {
            expected: product_name.to_string(),
            found: sub,
        };
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if exp < now {
        return LicenseStatus::Expired { expires: exp };
    }

    LicenseStatus::ValidLicense {
        licensee: aud,
        product: sub,
        tier,
        expires: exp,
    }
}

pub fn enforce_license_or_exit(product_name: &str) {
    match check_license(product_name) {
        LicenseStatus::AuthorMasterOverride { .. } => {
            // Instant silent authorized execution for Jeffrey
        }
        LicenseStatus::ValidLicense { licensee, tier, .. } => {
            eprintln!("[Aether License] Authenticated: {} ({})", licensee, tier);
        }
        LicenseStatus::MissingLicense { product } => {
            eprintln!("\x1b[31m[AETHER LICENSE REQUIRED]\x1b[0m Commercial execution of '{}' requires an Ed25519 license key.", product);
            eprintln!("Missing key in ~/.aether/license.key or env AETHER_LICENSE_KEY.");
            eprintln!(
                "Purchase license at https://aetherx86.github.io/#products (or PayPal @Aetherx86)"
            );
            std::process::exit(126);
        }
        LicenseStatus::InvalidSignature => {
            eprintln!("\x1b[31m[AETHER LICENSE INVALID]\x1b[0m Forged or corrupted Ed25519 cryptographic signature.");
            std::process::exit(126);
        }
        LicenseStatus::Expired { expires } => {
            eprintln!(
                "\x1b[31m[AETHER LICENSE EXPIRED]\x1b[0m License expired at timestamp {}.",
                expires
            );
            std::process::exit(126);
        }
        LicenseStatus::ProductMismatch { expected, found } => {
            eprintln!("\x1b[31m[AETHER LICENSE MISMATCH]\x1b[0m Key issued for '{}', but required for '{}'.", found, expected);
            std::process::exit(126);
        }
    }
}

fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    let mut clean = s.replace('-', "+").replace('_', "/");
    while !clean.len().is_multiple_of(4) {
        clean.push('=');
    }
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = TABLE.iter().position(|&c| c == bytes[i])?;
        let b1 = TABLE.iter().position(|&c| c == bytes[i + 1])?;
        out.push(((b0 << 2) | (b1 >> 4)) as u8);
        if bytes[i + 2] != b'=' {
            let b2 = TABLE.iter().position(|&c| c == bytes[i + 2])?;
            out.push((((b1 & 0xf) << 4) | (b2 >> 2)) as u8);
            if bytes[i + 3] != b'=' {
                let b3 = TABLE.iter().position(|&c| c == bytes[i + 3])?;
                out.push((((b2 & 0x3) << 6) | b3) as u8);
            }
        }
        i += 4;
    }
    Some(out)
}

fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", field);
    if let Some(pos) = json.find(&pattern) {
        let rest = &json[pos + pattern.len()..];
        if let Some(end) = rest.find('\"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn extract_json_number(json: &str, field: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", field);
    if let Some(pos) = json.find(&pattern) {
        let rest = json[pos + pattern.len()..].trim_start();
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return num_str.parse().ok();
    }
    None
}
