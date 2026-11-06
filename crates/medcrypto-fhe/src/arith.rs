//! Word-sized modular arithmetic.
//!
//! Reduction uses comparisons turned into masks rather than branches, so its timing does not depend on
//! the values. Primes are limited to 61 bits, which leaves headroom in the 128-bit products.

/// A prime modulus with what Barrett reduction needs precomputed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modulus {
    pub q: u64,
    bits: u32,
    mu: u64,
}

#[inline(always)]
fn conditional_subtract(x: u64, q: u64) -> u64 {
    x.wrapping_sub(q & ((x >= q) as u64).wrapping_neg())
}

impl Modulus {
    /// `q` must have between 20 and 61 bits.
    pub fn new(q: u64) -> Self {
        let bits = 64 - q.leading_zeros();
        assert!((20..=61).contains(&bits), "modulus must have 20 to 61 bits");
        Self {
            q,
            bits,
            mu: ((1u128 << (2 * bits)) / q as u128) as u64,
        }
    }

    /// Reduces any `x` below `2^(2 * bits)`, which covers every product of two reduced values.
    #[inline(always)]
    pub fn reduce_u128(&self, x: u128) -> u64 {
        let q1 = (x >> (self.bits - 1)) as u64;
        let q3 = ((q1 as u128 * self.mu as u128) >> (self.bits + 1)) as u64;
        let r = (x as u64).wrapping_sub(q3.wrapping_mul(self.q));
        conditional_subtract(conditional_subtract(r, self.q), self.q)
    }

    /// Reduces a word. Words can exceed `2^(2 * bits)` only for primes under 32 bits.
    #[inline(always)]
    pub fn reduce(&self, x: u64) -> u64 {
        if self.bits >= 32 {
            self.reduce_u128(x as u128)
        } else {
            x % self.q
        }
    }

    /// The residue of a signed integer of any size.
    pub fn reduce_i128(&self, x: i128) -> u64 {
        x.rem_euclid(self.q as i128) as u64
    }

    #[inline(always)]
    pub fn add(&self, a: u64, b: u64) -> u64 {
        conditional_subtract(a + b, self.q)
    }

    #[inline(always)]
    pub fn sub(&self, a: u64, b: u64) -> u64 {
        conditional_subtract(a + self.q - b, self.q)
    }

    #[inline(always)]
    pub fn neg(&self, a: u64) -> u64 {
        conditional_subtract(self.q - a, self.q)
    }

    #[inline(always)]
    pub fn mul(&self, a: u64, b: u64) -> u64 {
        self.reduce_u128(a as u128 * b as u128)
    }

    pub fn pow(&self, base: u64, mut exp: u64) -> u64 {
        let (mut result, mut b) = (1, self.reduce(base));
        while exp > 0 {
            if exp & 1 == 1 {
                result = self.mul(result, b);
            }
            b = self.mul(b, b);
            exp >>= 1;
        }
        result
    }

    /// The inverse, by Fermat's little theorem since `q` is prime.
    pub fn inv(&self, a: u64) -> u64 {
        self.pow(a, self.q - 2)
    }

    /// The constant that makes repeated multiplication by `w` fast, for [`Modulus::mul_shoup`].
    pub fn shoup(&self, w: u64) -> u64 {
        (((w as u128) << 64) / self.q as u128) as u64
    }

    /// `a * w mod q`, given `w_shoup = shoup(w)`.
    #[inline(always)]
    pub fn mul_shoup(&self, a: u64, w: u64, w_shoup: u64) -> u64 {
        let hi = ((w_shoup as u128 * a as u128) >> 64) as u64;
        conditional_subtract(
            a.wrapping_mul(w).wrapping_sub(hi.wrapping_mul(self.q)),
            self.q,
        )
    }
}

/// Deterministic Miller-Rabin, using a base set proven sufficient for every 64-bit integer.
pub fn is_prime(n: u64) -> bool {
    const BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    if n < 2 {
        return false;
    }
    for p in BASES {
        if n == p {
            return true;
        }
        if n.is_multiple_of(p) {
            return false;
        }
    }
    let (d, r) = (
        (n - 1) >> (n - 1).trailing_zeros(),
        (n - 1).trailing_zeros(),
    );
    let mul = |a: u64, b: u64| ((a as u128 * b as u128) % n as u128) as u64;
    let pow = |mut b: u64, mut e: u64| {
        let mut x = 1u64;
        while e > 0 {
            if e & 1 == 1 {
                x = mul(x, b);
            }
            b = mul(b, b);
            e >>= 1;
        }
        x
    };
    'witness: for a in BASES {
        let mut x = pow(a, d);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..r {
            x = mul(x, x);
            if x == n - 1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// The `count` largest primes below `2^bits` that are 1 mod `2 * degree`, which is what makes them
/// support a negacyclic NTT of that degree. The result is deterministic, so every party gets the same chain.
pub fn ntt_primes(bits: u32, degree: usize, count: usize) -> Vec<u64> {
    let step = 2 * degree as u64;
    let mut candidate = (1u64 << bits) - ((1u64 << bits) % step) + 1;
    let mut found = Vec::with_capacity(count);
    while found.len() < count {
        candidate -= step;
        assert!(
            candidate >> (bits - 1) == 1,
            "ran out of {bits}-bit NTT primes"
        );
        if is_prime(candidate) {
            found.push(candidate);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrett_and_shoup_agree_with_plain_division() {
        for q in ntt_primes(60, 8192, 1)
            .into_iter()
            .chain(ntt_primes(40, 8192, 1))
        {
            let m = Modulus::new(q);
            let mut x = 0x1234_5678_9abc_def1u64;
            for _ in 0..2000 {
                x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
                let (a, b) = (x % q, x.rotate_left(29) % q);
                let expected = ((a as u128 * b as u128) % q as u128) as u64;
                assert_eq!(m.mul(a, b), expected);
                assert_eq!(m.mul_shoup(a, b, m.shoup(b)), expected);
                assert_eq!(m.reduce(x), x % q);
            }
            assert_eq!(m.mul(m.inv(12345), 12345), 1);
        }
    }

    #[test]
    fn primes_have_the_required_form() {
        for q in ntt_primes(40, 16384, 8) {
            assert!(is_prime(q));
            assert_eq!(q % (2 * 16384), 1);
            assert_eq!(64 - q.leading_zeros(), 40);
        }
        assert!(!is_prime(18446744073709551557 - 2));
        assert!(is_prime(18446744073709551557));
    }
}
