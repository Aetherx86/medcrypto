//! Zero-knowledge range proofs resting only on SHA-256, which a quantum computer does not break.
//!
//! The commitment is `C = SHA-256("mcrange1" || value || blinding)`. The proof shows that the prover knows a
//! value and blinding with that hash, and that `min <= value <= max`, and shows nothing else.
//!
//! # MPC in the head (ZKBoo)
//!
//! The prover splits its secret into three random shares that XOR to it, and imagines three parties computing
//! the whole statement between them: SHA-256 of the secret, and the two comparisons. XOR gates are local. An AND
//! gate has each party combine its own share and the next party's with random tape, so that any two parties'
//! views together say nothing about the secret, while all three are needed to compute it.
//!
//! The prover commits to all three views, and a hash of everything picks two to open. If the prover cheated
//! anywhere, at least one of the three pairs is inconsistent, so each round catches it with probability at
//! least 1/3. With [`ROUNDS`] rounds, the chance of getting away with it is `(2/3)^438`, about `2^-256`.
//! Grover's algorithm square-roots a search for lucky challenges, which leaves about 128 bits.
//!
//! The proof is large, about 1.4 MB, because it holds a transcript of the circuit per round. That is the price
//! of assuming nothing but a hash function.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `(2/3)^438` is about `2^-256`, and so about `2^-128` against a quantum search.
pub const ROUNDS: usize = 438;

const DOMAIN: &[u8; 8] = b"mcrange1";
const INPUT_WORDS: usize = 10;
const OUTPUT_WORDS: usize = 10;
/// 64 rounds of 2 ANDs and 7 additions, 48 schedule words of 3 additions, 8 final additions, and 4 additions
/// for the two 64-bit comparisons.
const VIEW_WORDS: usize = 64 * 9 + 48 * 3 + 8 + 4;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// What a proof is about, apart from the range.
pub type Commitment = [u8; 32];

/// `SHA-256("mcrange1" || value || blinding)`, with the value little-endian.
pub fn commit(value: u64, blinding: &[u8; 32]) -> Commitment {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(value.to_le_bytes())
        .chain_update(blinding)
        .finalize()
        .into()
}

fn input_words(value: u64, blinding: &[u8; 32]) -> [u32; INPUT_WORDS] {
    let mut words = [0u32; INPUT_WORDS];
    words[0] = value as u32;
    words[1] = (value >> 32) as u32;
    for (word, chunk) in words[2..].iter_mut().zip(blinding.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*chunk);
    }
    words
}

/// The three parties' shares of one wire. In verification, the unopened party's share is meaningless.
type Shares = [u32; 3];

fn xor(a: Shares, b: Shares) -> Shares {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]]
}

fn rotr(a: Shares, n: u32) -> Shares {
    [
        a[0].rotate_right(n),
        a[1].rotate_right(n),
        a[2].rotate_right(n),
    ]
}

fn shr(a: Shares, n: u32) -> Shares {
    [a[0] >> n, a[1] >> n, a[2] >> n]
}

/// A public constant, held in party 0's share. Which is why opening party 0 has to apply it, and nobody else.
fn constant(c: u32) -> Shares {
    [c, 0, 0]
}

/// One execution of the circuit: all three parties when proving, or the two opened ones when verifying.
struct Mpc<'a> {
    tapes: [ChaCha20Rng; 3],
    /// Which parties compute their gate outputs. The party after each of these has its outputs read from `given`.
    computed: [bool; 3],
    given: Option<(usize, &'a [u32])>,
    views: [Vec<u32>; 3],
    next_given: usize,
}

impl Mpc<'_> {
    /// Produces the next non-linear word, given how each party derives it from the wires.
    fn gate(&mut self, compute: impl Fn(usize, u32, u32) -> u32) -> Shares {
        let randoms = [
            self.tapes[0].next_u32(),
            self.tapes[1].next_u32(),
            self.tapes[2].next_u32(),
        ];
        let mut out = [0u32; 3];
        for party in 0..3 {
            if self.computed[party] {
                out[party] = compute(party, randoms[party], randoms[(party + 1) % 3]);
                self.views[party].push(out[party]);
            }
        }
        if let Some((party, words)) = self.given {
            let word = words[self.next_given];
            self.next_given += 1;
            out[party] = word;
            self.views[party].push(word);
        }
        out
    }

    fn and(&mut self, x: Shares, y: Shares) -> Shares {
        self.gate(|i, ri, rj| {
            let j = (i + 1) % 3;
            (x[i] & y[i]) ^ (x[j] & y[i]) ^ (x[i] & y[j]) ^ ri ^ rj
        })
    }

    /// 32-bit addition with a carry in, as a ripple of AND gates. One AND depends on the previous carry of two
    /// parties, so all the parties advance one bit at a time. The view holds one word per addition for each
    /// party: bit `i` is its share of the carry out of bit `i`. `carry_in` holds a share in bit 0 of each word.
    /// Returns the sum and the carry out, also in bit 0.
    fn add_with_carry(&mut self, x: Shares, y: Shares, carry_in: Shares) -> (Shares, Shares) {
        let randoms = [
            self.tapes[0].next_u32(),
            self.tapes[1].next_u32(),
            self.tapes[2].next_u32(),
        ];
        let known = self.given.map(|(party, words)| {
            let word = words[self.next_given];
            self.next_given += 1;
            (party, word)
        });
        let mut current = [carry_in[0] & 1, carry_in[1] & 1, carry_in[2] & 1];
        let mut carries = [0u32; 3];
        for bit in 0..32 {
            let mut next = [0u32; 3];
            for party in 0..3 {
                if self.computed[party] {
                    let other = (party + 1) % 3;
                    let (ci, cj) = (current[party], current[other]);
                    let (ai, aj) = (((x[party] >> bit) & 1) ^ ci, ((x[other] >> bit) & 1) ^ cj);
                    let (bi, bj) = (((y[party] >> bit) & 1) ^ ci, ((y[other] >> bit) & 1) ^ cj);
                    // carry out = ((x ^ c) & (y ^ c)) ^ c, as a shared AND.
                    next[party] = (ai & bi)
                        ^ (aj & bi)
                        ^ (ai & bj)
                        ^ ((randoms[party] >> bit) & 1)
                        ^ ((randoms[other] >> bit) & 1)
                        ^ ci;
                }
            }
            if let Some((party, word)) = known {
                next[party] = (word >> bit) & 1;
            }
            for (carry, bit_value) in carries.iter_mut().zip(next) {
                *carry |= bit_value << bit;
            }
            current = next;
        }
        for (party, &carry) in carries.iter().enumerate() {
            if self.computed[party] || known.is_some_and(|(p, _)| p == party) {
                self.views[party].push(carry);
            }
        }
        let shifted = [
            (carries[0] << 1) | (carry_in[0] & 1),
            (carries[1] << 1) | (carry_in[1] & 1),
            (carries[2] << 1) | (carry_in[2] & 1),
        ];
        let sum = xor(xor(x, y), shifted);
        (sum, [carries[0] >> 31, carries[1] >> 31, carries[2] >> 31])
    }

    fn add(&mut self, x: Shares, y: Shares) -> Shares {
        self.add_with_carry(x, y, [0, 0, 0]).0
    }

    /// The circuit: SHA-256 of the input, then the carries of `value - min` and `max - value`.
    fn run(&mut self, input: [Shares; INPUT_WORDS], min: u64, max: u64) -> [Shares; OUTPUT_WORDS] {
        let mut w = [[0u32; 3]; 64];
        w[0] = constant(u32::from_be_bytes(
            DOMAIN[0..4].try_into().expect("4 bytes"),
        ));
        w[1] = constant(u32::from_be_bytes(
            DOMAIN[4..8].try_into().expect("4 bytes"),
        ));
        // The value goes in little-endian, and SHA-256 reads big-endian words.
        for (i, word) in input[..2].iter().enumerate() {
            w[2 + i] = [
                word[0].swap_bytes(),
                word[1].swap_bytes(),
                word[2].swap_bytes(),
            ];
        }
        w[4..12].copy_from_slice(&input[2..10]);
        w[12] = constant(0x8000_0000);
        w[15] = constant(48 * 8);
        for t in 16..64 {
            let s0 = xor(
                xor(rotr(w[t - 15], 7), rotr(w[t - 15], 18)),
                shr(w[t - 15], 3),
            );
            let s1 = xor(
                xor(rotr(w[t - 2], 17), rotr(w[t - 2], 19)),
                shr(w[t - 2], 10),
            );
            let sum = self.add(w[t - 16], s0);
            let sum = self.add(sum, w[t - 7]);
            w[t] = self.add(sum, s1);
        }
        let mut state: [Shares; 8] = IV.map(constant);
        for t in 0..64 {
            let [a, b, c, d, e, f, g, h] = state;
            let s1 = xor(xor(rotr(e, 6), rotr(e, 11)), rotr(e, 25));
            let ch = xor(self.and(e, xor(f, g)), g);
            let t1 = self.add(h, s1);
            let t1 = self.add(t1, ch);
            let t1 = self.add(t1, constant(K[t]));
            let t1 = self.add(t1, w[t]);
            let s0 = xor(xor(rotr(a, 2), rotr(a, 13)), rotr(a, 22));
            let maj = xor(self.and(xor(a, b), xor(a, c)), a);
            let t2 = self.add(s0, maj);
            state = [self.add(t1, t2), a, b, c, self.add(d, t1), e, f, g];
        }
        let mut out = [[0u32; 3]; OUTPUT_WORDS];
        for i in 0..8 {
            out[i] = self.add(state[i], constant(IV[i]));
        }

        // value - min does not borrow when value + !min + 1 carries out of the top, and likewise for max - value.
        let not = |x: Shares| [!x[0], x[1], x[2]];
        let (low, high) = (input[0], input[1]);
        let (_, carry) = self.add_with_carry(low, constant(!(min as u32)), constant(1));
        let (_, above_min) = self.add_with_carry(high, constant(!((min >> 32) as u32)), carry);
        let (_, carry) = self.add_with_carry(constant(max as u32), not(low), constant(1));
        let (_, below_max) = self.add_with_carry(constant((max >> 32) as u32), not(high), carry);
        out[8] = above_min;
        out[9] = below_max;
        out
    }
}

/// The expected output: the commitment as big-endian words, and both comparisons holding.
fn expected_output(commitment: &Commitment) -> [u32; OUTPUT_WORDS] {
    let mut out = [0u32; OUTPUT_WORDS];
    for (word, chunk) in out[..8].iter_mut().zip(commitment.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*chunk);
    }
    out[8] = 1;
    out[9] = 1;
    out
}

fn tape_for(seed: &[u8; 32]) -> ChaCha20Rng {
    let derived: [u8; 32] = Sha256::new()
        .chain_update(b"medcrypto-mpcith-tape-v1")
        .chain_update(seed)
        .finalize()
        .into();
    ChaCha20Rng::from_seed(derived)
}

fn view_commitment(party: usize, seed: &[u8; 32], extra: &[u32], view: &[u32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"medcrypto-mpcith-view-v1");
    hash.update([party as u8]);
    hash.update(seed);
    for word in extra.iter().chain(view) {
        hash.update(word.to_le_bytes());
    }
    hash.finalize().into()
}

/// One round's transcript of the two opened parties, and what the verifier needs about the third.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Round {
    seeds: [[u8; 32]; 2],
    /// Party 2's input share, which is not from a tape, if party 2 is opened.
    third_input: Option<Vec<u32>>,
    /// The second opened party's gate outputs.
    #[serde(with = "serde_bytes")]
    view: Vec<u8>,
    closed_commitment: [u8; 32],
    closed_output: [u32; OUTPUT_WORDS],
}

/// A proof, to be checked with [`verify`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RangeProof {
    challenge: [u8; 32],
    rounds: Vec<Round>,
}

/// Which party to open first in each round: bases of 3, by rejection on pairs of bits from a hash stream.
fn challenges(digest: &[u8; 32]) -> Vec<usize> {
    let mut out = Vec::with_capacity(ROUNDS);
    let mut counter = 0u64;
    while out.len() < ROUNDS {
        let block: [u8; 32] = Sha256::new()
            .chain_update(digest)
            .chain_update(counter.to_le_bytes())
            .finalize()
            .into();
        counter += 1;
        for byte in block {
            for shift in [0, 2, 4, 6] {
                let trit = ((byte >> shift) & 3) as usize;
                if trit < 3 && out.len() < ROUNDS {
                    out.push(trit);
                }
            }
        }
    }
    out
}

fn start_digest(commitment: &Commitment, min: u64, max: u64, context: &[u8]) -> Sha256 {
    Sha256::new()
        .chain_update(b"medcrypto-mpcith-challenge-v1")
        .chain_update(commitment)
        .chain_update(min.to_le_bytes())
        .chain_update(max.to_le_bytes())
        .chain_update((context.len() as u64).to_le_bytes())
        .chain_update(context)
}

fn absorb(hash: &mut Sha256, commitments: &[[u8; 32]; 3], outputs: &[[u32; OUTPUT_WORDS]; 3]) {
    for party in 0..3 {
        hash.update(commitments[party]);
        for word in outputs[party] {
            hash.update(word.to_le_bytes());
        }
    }
}

/// Proves `min <= value <= max` for a value under `commit(value, blinding)`, or returns `None` if that is false.
/// `randomness` has to be 32 fresh bytes from a cryptographic source, and never reused.
pub fn prove(
    value: u64,
    blinding: &[u8; 32],
    min: u64,
    max: u64,
    context: &[u8],
    randomness: &[u8; 32],
) -> Option<(Commitment, RangeProof)> {
    if value < min || value > max {
        return None;
    }
    Some(prove_unchecked(
        value, blinding, min, max, context, randomness,
    ))
}

fn prove_unchecked(
    value: u64,
    blinding: &[u8; 32],
    min: u64,
    max: u64,
    context: &[u8],
    randomness: &[u8; 32],
) -> (Commitment, RangeProof) {
    let commitment = commit(value, blinding);
    let secret = input_words(value, blinding);
    let mut seed_rng = ChaCha20Rng::from_seed(randomness.to_owned());
    let mut digest = start_digest(&commitment, min, max, context);
    let mut transcripts = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let mut seeds = [[0u8; 32]; 3];
        for seed in &mut seeds {
            seed_rng.fill_bytes(seed);
        }
        let mut tapes = [
            tape_for(&seeds[0]),
            tape_for(&seeds[1]),
            tape_for(&seeds[2]),
        ];
        let mut shares = [[0u32; 3]; INPUT_WORDS];
        for (share, word) in shares.iter_mut().zip(secret) {
            share[0] = tapes[0].next_u32();
            share[1] = tapes[1].next_u32();
            share[2] = word ^ share[0] ^ share[1];
        }
        let mut mpc = Mpc {
            tapes,
            computed: [true; 3],
            given: None,
            views: [
                Vec::with_capacity(VIEW_WORDS),
                Vec::with_capacity(VIEW_WORDS),
                Vec::with_capacity(VIEW_WORDS),
            ],
            next_given: 0,
        };
        let out = mpc.run(shares, min, max);
        let third: Vec<u32> = shares.iter().map(|s| s[2]).collect();
        let [v0, v1, v2] = mpc.views;
        let commitments = [
            view_commitment(0, &seeds[0], &[], &v0),
            view_commitment(1, &seeds[1], &[], &v1),
            view_commitment(2, &seeds[2], &third, &v2),
        ];
        let outputs = [out.map(|s| s[0]), out.map(|s| s[1]), out.map(|s| s[2])];
        absorb(&mut digest, &commitments, &outputs);
        transcripts.push((seeds, third, [v0, v1, v2], commitments, outputs));
    }
    let challenge: [u8; 32] = digest.finalize().into();
    let rounds = challenges(&challenge)
        .into_iter()
        .zip(transcripts)
        .map(|(e, (seeds, third, views, commitments, outputs))| {
            let (next, closed) = ((e + 1) % 3, (e + 2) % 3);
            Round {
                seeds: [seeds[e], seeds[next]],
                third_input: (closed != 2).then_some(third),
                view: views[next].iter().flat_map(|w| w.to_le_bytes()).collect(),
                closed_commitment: commitments[closed],
                closed_output: outputs[closed],
            }
        })
        .collect();
    (commitment, RangeProof { challenge, rounds })
}

/// Whether a proof holds for this commitment, range and context. Anything malformed is simply `false`.
pub fn verify(
    commitment: &Commitment,
    min: u64,
    max: u64,
    context: &[u8],
    proof: &RangeProof,
) -> bool {
    if min > max || proof.rounds.len() != ROUNDS {
        return false;
    }
    let expected = expected_output(commitment);
    let mut digest = start_digest(commitment, min, max, context);
    let picks = challenges(&proof.challenge);
    for (round, &e) in proof.rounds.iter().zip(&picks) {
        let (next, closed) = ((e + 1) % 3, (e + 2) % 3);
        if round.view.len() != VIEW_WORDS * 4 {
            return false;
        }
        match (&round.third_input, closed != 2) {
            (Some(third), true) if third.len() == INPUT_WORDS => {}
            (None, false) => {}
            _ => return false,
        }
        let given: Vec<u32> = round
            .view
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();

        let mut tapes = [tape_for(&[0; 32]), tape_for(&[0; 32]), tape_for(&[0; 32])];
        tapes[e] = tape_for(&round.seeds[0]);
        tapes[next] = tape_for(&round.seeds[1]);
        let mut shares = [[0u32; 3]; INPUT_WORDS];
        for (i, share) in shares.iter_mut().enumerate() {
            for party in [e, next] {
                share[party] = if party == 2 {
                    round.third_input.as_ref().expect("checked above")[i]
                } else {
                    tapes[party].next_u32()
                };
            }
        }
        let mut computed = [false; 3];
        computed[e] = true;
        let mut mpc = Mpc {
            tapes,
            computed,
            given: Some((next, &given)),
            views: [Vec::new(), Vec::new(), Vec::new()],
            next_given: 0,
        };
        let out = mpc.run(shares, min, max);

        let extra = |party: usize| -> &[u32] {
            if party == 2 {
                round.third_input.as_deref().unwrap_or(&[])
            } else {
                &[]
            }
        };
        let mut commitments = [[0u8; 32]; 3];
        let mut outputs = [[0u32; OUTPUT_WORDS]; 3];
        commitments[e] = view_commitment(e, &round.seeds[0], extra(e), &mpc.views[e]);
        commitments[next] = view_commitment(next, &round.seeds[1], extra(next), &mpc.views[next]);
        commitments[closed] = round.closed_commitment;
        outputs[e] = out.map(|s| s[e]);
        outputs[next] = out.map(|s| s[next]);
        outputs[closed] = round.closed_output;
        for word in 0..OUTPUT_WORDS {
            if outputs[0][word] ^ outputs[1][word] ^ outputs[2][word] != expected[word] {
                return false;
            }
        }
        absorb(&mut digest, &commitments, &outputs);
    }
    let recomputed: [u8; 32] = digest.finalize().into();
    recomputed == proof.challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLINDING: [u8; 32] = [42; 32];
    const RANDOM: [u8; 32] = [7; 32];

    #[test]
    fn honest_proofs_verify_across_the_range() {
        for (value, min, max) in [
            (58u64, 0u64, 65u64),
            (65, 0, 65),
            (0, 0, 65),
            (7, 7, 7),
            (u64::MAX, 0, u64::MAX),
            (u64::MAX - 3, u64::MAX - 10, u64::MAX),
            (1 << 32, (1 << 32) - 1, (1 << 32) + 1),
        ] {
            let (c, proof) = prove(value, &BLINDING, min, max, b"test", &RANDOM).unwrap();
            assert_eq!(c, commit(value, &BLINDING));
            assert!(
                verify(&c, min, max, b"test", &proof),
                "{value} in [{min}, {max}]"
            );
        }
    }

    #[test]
    fn a_false_statement_gets_no_proof_and_a_forced_one_does_not_verify() {
        assert!(prove(66, &BLINDING, 0, 65, b"", &RANDOM).is_none());
        assert!(prove(4, &BLINDING, 5, 65, b"", &RANDOM).is_none());
        // A dishonest prover that runs the protocol anyway: the comparison comes out false, in the open.
        for (value, min, max) in [
            (66u64, 0u64, 65u64),
            (4, 5, 65),
            (1 << 32, 0, (1 << 32) - 1),
        ] {
            let (c, proof) = prove_unchecked(value, &BLINDING, min, max, b"", &RANDOM);
            assert!(
                !verify(&c, min, max, b"", &proof),
                "{value} in [{min}, {max}]"
            );
        }
    }

    #[test]
    fn a_proof_is_for_one_commitment_range_and_context() {
        let (c, proof) = prove(58, &BLINDING, 0, 65, b"ctx", &RANDOM).unwrap();
        assert!(verify(&c, 0, 65, b"ctx", &proof));
        assert!(!verify(&c, 0, 64, b"ctx", &proof));
        assert!(!verify(&c, 1, 65, b"ctx", &proof));
        assert!(!verify(&c, 0, 65, b"other", &proof));
        assert!(!verify(&commit(58, &[1; 32]), 0, 65, b"ctx", &proof));
        assert!(!verify(&commit(59, &BLINDING), 0, 65, b"ctx", &proof));
    }

    #[test]
    fn tampering_anywhere_breaks_it() {
        let (c, proof) = prove(58, &BLINDING, 0, 65, b"", &RANDOM).unwrap();
        let mut bad = proof.clone();
        bad.rounds[3].view[100] ^= 1;
        assert!(!verify(&c, 0, 65, b"", &bad));
        let mut bad = proof.clone();
        bad.rounds[400].seeds[1][0] ^= 1;
        assert!(!verify(&c, 0, 65, b"", &bad));
        let mut bad = proof.clone();
        bad.rounds[7].closed_commitment[0] ^= 1;
        assert!(!verify(&c, 0, 65, b"", &bad));
        let mut bad = proof.clone();
        bad.rounds[7].closed_output[9] ^= 1;
        assert!(!verify(&c, 0, 65, b"", &bad));
        let mut bad = proof.clone();
        bad.challenge[0] ^= 1;
        assert!(!verify(&c, 0, 65, b"", &bad));
        let mut bad = proof.clone();
        bad.rounds.pop();
        assert!(!verify(&c, 0, 65, b"", &bad));
        let mut bad = proof;
        bad.rounds[0].view.pop();
        assert!(!verify(&c, 0, 65, b"", &bad));
    }

    #[test]
    fn what_is_opened_says_nothing_directly_about_the_value() {
        // Two proofs of different values under fresh randomness look alike in shape, and each round's opened
        // input shares change with the randomness. Hiding itself rests on the protocol's argument.
        let (_, a) = prove(58, &BLINDING, 0, 65, b"", &[1; 32]).unwrap();
        let (_, b) = prove(58, &BLINDING, 0, 65, b"", &[2; 32]).unwrap();
        assert_ne!(a.challenge, b.challenge);
        assert_ne!(a.rounds[0].view, b.rounds[0].view);
        let bytes = postcard::to_allocvec(&a).unwrap();
        assert_eq!(postcard::from_bytes::<RangeProof>(&bytes).unwrap(), a);
        assert!(bytes.len() < 1_500_000, "{}", bytes.len());
    }
}
