//! Polynomials in the Residue Number System.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;
use zeroize::Zeroize;

/// One polynomial, as one vector of `N` residues per prime. Which primes those are is up to whoever
/// holds it. Every polynomial in a key or a ciphertext is stored in the NTT domain.
#[derive(Clone, PartialEq, Eq)]
pub struct RnsPoly {
    pub(crate) limbs: Vec<Vec<u64>>,
}

impl core::fmt::Debug for RnsPoly {
    // Deliberately no coefficients, so that a stray debug print cannot leak key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RnsPoly({} limbs of {})",
            self.limbs.len(),
            self.degree()
        )
    }
}

impl RnsPoly {
    pub fn zero(degree: usize, limbs: usize) -> Self {
        Self {
            limbs: vec![vec![0; degree]; limbs],
        }
    }

    pub fn degree(&self) -> usize {
        self.limbs.first().map_or(0, Vec::len)
    }

    pub fn limb_count(&self) -> usize {
        self.limbs.len()
    }

    /// The residues modulo one prime, for inspection.
    pub fn limb(&self, index: usize) -> &[u64] {
        &self.limbs[index]
    }

    /// The first residues of each prime, as a short fingerprint for display.
    pub fn preview(&self, count: usize) -> Vec<u64> {
        self.limbs
            .first()
            .map(|l| l.iter().take(count).copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn wipe(&mut self) {
        for limb in &mut self.limbs {
            limb.zeroize();
        }
    }
}

fn to_le_bytes(limb: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(limb.len() * 8);
    for word in limb {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn from_le_bytes(bytes: &[u8]) -> Option<Vec<u64>> {
    if !bytes.len().is_multiple_of(8) {
        return None;
    }
    Some(
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect(),
    )
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

// Hexadecimal in JSON, raw bytes in binary formats. A plain list of numbers would be several times the size.
impl Serialize for RnsPoly {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            let hex: Vec<String> = self.limbs.iter().map(|l| to_hex(&to_le_bytes(l))).collect();
            hex.serialize(serializer)
        } else {
            let raw: Vec<ByteBuf> = self
                .limbs
                .iter()
                .map(|l| ByteBuf::from(to_le_bytes(l)))
                .collect();
            raw.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RnsPoly {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: Vec<Vec<u8>> = if deserializer.is_human_readable() {
            Vec::<String>::deserialize(deserializer)?
                .iter()
                .map(|h| from_hex(h).ok_or_else(|| D::Error::custom("invalid hexadecimal")))
                .collect::<Result<_, _>>()?
        } else {
            Vec::<ByteBuf>::deserialize(deserializer)?
                .into_iter()
                .map(ByteBuf::into_vec)
                .collect()
        };
        let limbs = raw
            .iter()
            .map(|b| from_le_bytes(b).ok_or_else(|| D::Error::custom("a limb is not whole words")))
            .collect::<Result<_, _>>()?;
        Ok(Self { limbs })
    }
}
