//! The canonical embedding: real vectors in slots, on one side, and polynomial coefficients on the other.
//!
//! Slot `j` is the polynomial evaluated at `zeta^(5^j)`, where `zeta` is a primitive `2N`-th complex root
//! of unity. That order is what makes the automorphism `X -> X^(5^k)` rotate the slots by `k`, and it
//! makes coefficient-wise ring multiplication act as slot-wise multiplication.

#[derive(Clone, Copy)]
struct Complex(f64, f64);

impl Complex {
    #[inline]
    fn add(self, o: Self) -> Self {
        Complex(self.0 + o.0, self.1 + o.1)
    }
    #[inline]
    fn sub(self, o: Self) -> Self {
        Complex(self.0 - o.0, self.1 - o.1)
    }
    #[inline]
    fn mul(self, o: Self) -> Self {
        Complex(self.0 * o.0 - self.1 * o.1, self.0 * o.1 + self.1 * o.0)
    }
}

#[derive(Clone, Debug)]
pub struct Encoder {
    degree: usize,
    roots: Vec<(f64, f64)>,
    rotation_group: Vec<u64>,
}

impl Encoder {
    pub fn new(degree: usize) -> Self {
        let m = 2 * degree;
        let roots = (0..=m)
            .map(|j| {
                let angle = 2.0 * core::f64::consts::PI * j as f64 / m as f64;
                (angle.cos(), angle.sin())
            })
            .collect();
        let mut rotation_group = Vec::with_capacity(degree / 2);
        let mut power = 1u64;
        for _ in 0..degree / 2 {
            rotation_group.push(power);
            power = (power * 5) % m as u64;
        }
        Self {
            degree,
            roots,
            rotation_group,
        }
    }

    pub fn slots(&self) -> usize {
        self.degree / 2
    }

    fn bit_reverse_permute(v: &mut [Complex]) {
        let bits = v.len().trailing_zeros();
        for i in 0..v.len() {
            let j = i.reverse_bits() >> (usize::BITS - bits);
            if i < j {
                v.swap(i, j);
            }
        }
    }

    fn root(&self, index: usize) -> Complex {
        let (re, im) = self.roots[index];
        Complex(re, im)
    }

    fn special_fft(&self, v: &mut [Complex]) {
        let m = 2 * self.degree;
        let size = v.len();
        Self::bit_reverse_permute(v);
        let mut len = 2;
        while len <= size {
            let (half, quarter_period) = (len / 2, 4 * len);
            for start in (0..size).step_by(len) {
                for j in 0..half {
                    let index =
                        (self.rotation_group[j] as usize % quarter_period) * m / quarter_period;
                    let u = v[start + j];
                    let t = v[start + j + half].mul(self.root(index));
                    v[start + j] = u.add(t);
                    v[start + j + half] = u.sub(t);
                }
            }
            len *= 2;
        }
    }

    fn special_ifft(&self, v: &mut [Complex]) {
        let m = 2 * self.degree;
        let size = v.len();
        let mut len = size;
        while len >= 2 {
            let (half, quarter_period) = (len / 2, 4 * len);
            for start in (0..size).step_by(len) {
                for j in 0..half {
                    let index = (quarter_period - self.rotation_group[j] as usize % quarter_period)
                        * m
                        / quarter_period;
                    let (a, b) = (v[start + j], v[start + j + half]);
                    v[start + j] = a.add(b);
                    v[start + j + half] = a.sub(b).mul(self.root(index));
                }
            }
            len /= 2;
        }
        Self::bit_reverse_permute(v);
        let inverse = 1.0 / size as f64;
        for x in v.iter_mut() {
            *x = Complex(x.0 * inverse, x.1 * inverse);
        }
    }

    /// Real slot values to real polynomial coefficients, before any scaling. Unused slots are zero.
    pub fn encode(&self, values: &[f64]) -> Vec<f64> {
        let half = self.slots();
        let mut v = vec![Complex(0.0, 0.0); half];
        for (slot, &value) in v.iter_mut().zip(values) {
            *slot = Complex(value, 0.0);
        }
        self.special_ifft(&mut v);
        let mut coefficients = vec![0.0; self.degree];
        for (i, x) in v.iter().enumerate() {
            coefficients[i] = x.0;
            coefficients[i + half] = x.1;
        }
        coefficients
    }

    /// Polynomial coefficients to all slot values. The imaginary parts are only noise, and are dropped.
    pub fn decode(&self, coefficients: &[f64]) -> Vec<f64> {
        let half = self.slots();
        let mut v: Vec<Complex> = (0..half)
            .map(|i| Complex(coefficients[i], coefficients[i + half]))
            .collect();
        self.special_fft(&mut v);
        v.iter().map(|x| x.0).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips() {
        let encoder = Encoder::new(64);
        let values: Vec<f64> = (0..32).map(|i| i as f64 * 1.5 - 7.0).collect();
        let decoded = encoder.decode(&encoder.encode(&values));
        for (a, b) in values.iter().zip(&decoded) {
            assert!((a - b).abs() < 1e-9, "{a} vs {b}");
        }
    }

    #[test]
    fn ring_multiplication_is_slot_multiplication() {
        let n = 64;
        let encoder = Encoder::new(n);
        let a: Vec<f64> = (0..32).map(|i| i as f64 + 1.0).collect();
        let b: Vec<f64> = (0..32).map(|i| 3.0 - i as f64 * 0.25).collect();
        let (ca, cb) = (encoder.encode(&a), encoder.encode(&b));
        let mut product = vec![0.0; n];
        for i in 0..n {
            for j in 0..n {
                if i + j < n {
                    product[i + j] += ca[i] * cb[j];
                } else {
                    product[i + j - n] -= ca[i] * cb[j];
                }
            }
        }
        let decoded = encoder.decode(&product);
        for i in 0..32 {
            assert!((decoded[i] - a[i] * b[i]).abs() < 1e-8);
        }
    }
}
