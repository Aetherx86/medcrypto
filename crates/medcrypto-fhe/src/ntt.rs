//! The negacyclic number theoretic transform over `Z_q[X] / (X^N + 1)`.

use crate::arith::Modulus;

/// Precomputed powers of a primitive `2N`-th root of unity for one prime.
///
/// After the forward transform, position `i` holds the polynomial evaluated at `psi^(2 * brv(i) + 1)`,
/// where `brv` reverses `log2 N` bits. [`galois_permutation`] depends on this.
#[derive(Clone, Debug)]
pub struct NttTable {
    pub modulus: Modulus,
    degree: usize,
    psi: Vec<u64>,
    psi_shoup: Vec<u64>,
    inv_psi: Vec<u64>,
    inv_psi_shoup: Vec<u64>,
    inv_degree: u64,
    inv_degree_shoup: u64,
}

fn bit_reverse(x: usize, bits: u32) -> usize {
    x.reverse_bits() >> (usize::BITS - bits)
}

impl NttTable {
    pub fn new(q: u64, degree: usize) -> Self {
        let modulus = Modulus::new(q);
        let log_n = degree.trailing_zeros();
        // The smallest qualifying root, so that the transform is the same for everybody.
        let root = (2..)
            .map(|x| modulus.pow(x, (q - 1) / (2 * degree as u64)))
            .find(|&r| modulus.pow(r, degree as u64) == q - 1)
            .expect("q is 1 mod 2N, so a root exists");
        let inv_root = modulus.inv(root);
        let (mut psi, mut inv_psi) = (vec![0u64; degree], vec![0u64; degree]);
        let (mut power, mut inv_power) = (1u64, 1u64);
        for i in 0..degree {
            let j = bit_reverse(i, log_n);
            psi[j] = power;
            inv_psi[j] = inv_power;
            power = modulus.mul(power, root);
            inv_power = modulus.mul(inv_power, inv_root);
        }
        let psi_shoup = psi.iter().map(|&w| modulus.shoup(w)).collect();
        let inv_psi_shoup = inv_psi.iter().map(|&w| modulus.shoup(w)).collect();
        let inv_degree = modulus.inv(degree as u64);
        Self {
            modulus,
            degree,
            psi,
            psi_shoup,
            inv_psi,
            inv_psi_shoup,
            inv_degree,
            inv_degree_shoup: modulus.shoup(inv_degree),
        }
    }

    /// Coefficients to evaluations, in place.
    pub fn forward(&self, a: &mut [u64]) {
        let m = self.modulus;
        let n = self.degree;
        let mut t = n;
        let mut groups = 1;
        while groups < n {
            t /= 2;
            for i in 0..groups {
                let (w, ws) = (self.psi[groups + i], self.psi_shoup[groups + i]);
                let start = 2 * i * t;
                let (left, right) = a[start..start + 2 * t].split_at_mut(t);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    let v = m.mul_shoup(*y, w, ws);
                    let u = *x;
                    *x = m.add(u, v);
                    *y = m.sub(u, v);
                }
            }
            groups *= 2;
        }
    }

    /// Evaluations to coefficients, in place.
    pub fn inverse(&self, a: &mut [u64]) {
        let m = self.modulus;
        let n = self.degree;
        let mut t = 1;
        let mut groups = n;
        while groups > 1 {
            let half = groups / 2;
            let mut start = 0;
            for i in 0..half {
                let (w, ws) = (self.inv_psi[half + i], self.inv_psi_shoup[half + i]);
                let (left, right) = a[start..start + 2 * t].split_at_mut(t);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    let (u, v) = (*x, *y);
                    *x = m.add(u, v);
                    *y = m.mul_shoup(m.sub(u, v), w, ws);
                }
                start += 2 * t;
            }
            t *= 2;
            groups = half;
        }
        for x in a.iter_mut() {
            *x = m.mul_shoup(*x, self.inv_degree, self.inv_degree_shoup);
        }
    }
}

/// For the automorphism `X -> X^g`, where position `i` of the transformed polynomial comes from in the
/// evaluation domain. No transform is needed to apply one, just this permutation.
pub fn galois_permutation(degree: usize, g: u64) -> Vec<u32> {
    let log_n = degree.trailing_zeros();
    let mask = 2 * degree as u64 - 1;
    (0..degree)
        .map(|i| {
            let k = 2 * bit_reverse(i, log_n) as u64 + 1;
            let image = k.wrapping_mul(g) & mask;
            bit_reverse(((image - 1) / 2) as usize, log_n) as u32
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::ntt_primes;

    fn pseudo_random(q: u64, n: usize, seed: u64) -> Vec<u64> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(23) ^ 0x5bd1;
                x % q
            })
            .collect()
    }

    #[test]
    fn round_trip_and_negacyclic_convolution() {
        let n = 64;
        let q = ntt_primes(40, n, 1)[0];
        let table = NttTable::new(q, n);
        let m = table.modulus;
        let (a, b) = (pseudo_random(q, n, 1), pseudo_random(q, n, 2));

        let mut schoolbook = vec![0u64; n];
        for i in 0..n {
            for j in 0..n {
                let product = m.mul(a[i], b[j]);
                schoolbook[(i + j) % n] = if i + j < n {
                    m.add(schoolbook[(i + j) % n], product)
                } else {
                    m.sub(schoolbook[(i + j) % n], product)
                };
            }
        }

        let (mut fa, mut fb) = (a.clone(), b.clone());
        table.forward(&mut fa);
        table.forward(&mut fb);
        let mut product: Vec<u64> = fa.iter().zip(&fb).map(|(&x, &y)| m.mul(x, y)).collect();
        table.inverse(&mut product);
        assert_eq!(product, schoolbook);

        table.inverse(&mut fa);
        assert_eq!(fa, a);
    }

    #[test]
    fn the_permutation_matches_the_coefficient_automorphism() {
        let n = 64;
        let q = ntt_primes(40, n, 1)[0];
        let table = NttTable::new(q, n);
        let m = table.modulus;
        let a = pseudo_random(q, n, 3);
        for g in [5u64, 25, 2 * n as u64 - 1] {
            // Directly: coefficient i moves to position i * g, with a sign flip past X^N.
            let mut expected = vec![0u64; n];
            for (i, &c) in a.iter().enumerate() {
                let position = (i as u64 * g) % (2 * n as u64);
                if position < n as u64 {
                    expected[position as usize] = c;
                } else {
                    expected[position as usize - n] = m.neg(c);
                }
            }
            table.forward(&mut expected);
            let mut f = a.clone();
            table.forward(&mut f);
            let permuted: Vec<u64> = galois_permutation(n, g)
                .iter()
                .map(|&i| f[i as usize])
                .collect();
            assert_eq!(permuted, expected);
        }
    }
}
