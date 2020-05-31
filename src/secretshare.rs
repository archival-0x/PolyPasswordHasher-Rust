//! Implementation of threshold secret sharing scheme with Lagrange polynomial interpolation.

use sodiumoxide::randombytes;

use crate::math::polynomial;

/// `ShamirSecret` is a wrapper struct over parameters
/// necessary in order to perform secret-sharing and
/// polynomial interpolation.
#[derive(Debug, Clone)]
pub struct ShamirSecret {
    pub threshold: u8,
    pub secretdata: Option<Vec<u8>>,
    pub coefficients: Vec<Vec<u8>>,
}

impl ShamirSecret {
    /// `new()` generates a new ShamirSecret struct, with randomly generated coefficients. It
    /// consumes a threshold, and an optional input buffer
    pub fn new(threshold: u8, secretdata: Option<Vec<u8>>) -> ShamirSecret {
        // initialize struct to hold raw coefficients
        let mut coefficients: Vec<Vec<u8>> = vec![];

        if let Some(data) = secretdata {
            // initialize random bytes from threshold size
            let rand_bytes = randombytes::randombytes((threshold - 1) as usize);

            // Secret-sharing will be applied for each byte of the secret
            for secretbyte in &data {
                let mut coefficient: Vec<u8> = vec![*secretbyte];
                for r in rand_bytes.iter() {
                    coefficient.push(*r);
                }
                coefficients.push(coefficient);
            }

            return ShamirSecret {
                threshold: threshold,
                secretdata: Some(data),
                coefficients: coefficients,
            };

        // return new ShamirSecret with no secretdata, if no secret was specified
        } else {
            return ShamirSecret {
                threshold: threshold,
                secretdata: None,
                coefficients: coefficients,
            };
        }
    }

    pub fn is_valid_share(&self, share: Vec<u8>) -> bool {
        if self.coefficients.len() == 0 {
            panic!("Coefficients were not initialized!");
        }

        let x: u8 = share[0];
        self.compute_share(x) == share
    }

    /// computes shares and returns a tuple representing (x, f(x))
    pub fn compute_share(&self, x: u8) -> Vec<u8> {
        if x < 1 {
            panic!("Cannot be smaller than 1 or greater than 255");
        }
        if self.coefficients.len() == 0 {
            panic!("Coefficients were not initialized!");
        }

        let mut sharebytes: Vec<u8> = vec![];

        let coefficients = self.coefficients.clone();
        for coefficient in coefficients {
            let share = polynomial::compute_polynomial(x, coefficient);
            sharebytes.push(share);
        }
        sharebytes.insert(0, x);
        sharebytes
    }

    /// recover secretdata by passing vector with shares equal to threshold
    pub fn recover_secretdata(&mut self, shares: Vec<Vec<u8>>) {
        let mut newshares: Vec<Vec<u8>> = vec![];

        for share in shares.iter() {
            if !newshares.contains(share) {
                newshares.push(share.clone());
            }
        }

        let shares = newshares.clone();
        if self.threshold as usize > shares.len() {
            panic!(
                "Threshold: {} is smaller than the number of shares: {}",
                self.threshold,
                shares.len()
            );
        }

        let mut xs: Vec<u8> = vec![];
        for share in shares.iter() {
            if xs.contains(&share[0]) {
                panic!("Different shares with the same byte: {:?}", share[0]);
            }
            if share.len() != shares[0].len() {
                panic!("Shares have different lengths!");
            }
            xs.push(share[0].clone());
        }

        let mut mycoefficients: Vec<u8> = vec![];
        let mut mysecretdata: Vec<u8> = vec![];

        let byte_walk = shares[0].len() - 1;

        for byte_to_use in 0..byte_walk {
            let mut fxs: Vec<u8> = vec![];
            for share in shares.clone() {
                fxs.push(share[1..][byte_to_use].clone());
            }

            let result_polynomial = polynomial::full_lagrange(xs.clone(), fxs);
            for coefficient in result_polynomial[..].iter() {
                mycoefficients.push(*coefficient);
            }
            mysecretdata.push(result_polynomial[0].clone());
        }
        self.coefficients = vec![mycoefficients];
        self.secretdata = Some(mysecretdata.to_vec())
    }
}
