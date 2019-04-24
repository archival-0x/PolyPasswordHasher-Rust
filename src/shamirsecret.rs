//!
//! shamirsecret.rs
//!
//!     Implementation of threshold secret sharing
//!     scheme with Lagrange polynomial interpolation.

mod math;
use math::helpers::*;

use ring::rand::{SecureRandom, SystemRandom};


#[cfg(test)]
mod tests {
    use super::ShamirSecret;

    #[test]
    fn test_full_lagrange(){
         assert_eq!(super::_full_lagrange(vec![2, 4, 5], vec![14, 30, 32]), vec![43, 168, 150]);
    }

    #[test]
    fn test_generate_secret(){
        let message = String::from("Secret message");
        let _ = ShamirSecret::new(5, Some(message));
    }

    #[test]
    fn test_recover_secret(){
        let secret = ShamirSecret::new(3, Some("Hello".to_string()));

        // Calculate 3 new shares, since k = 3
        let a = secret.compute_share(1);
        let b = secret.compute_share(2);
        let c = secret.compute_share(3);

        // Notice how first element is always x
        println!("A: {:?}\nB: {:?}\nC: {:?}", a, b, c);

        // New ShamirSecret object with no secret.
        let mut newsecret = ShamirSecret::new(3, None);

        // Recover with vector of 3 shares. This sets secret for new
        // ShamirSecret object
        let _ = newsecret.recover_secretdata(vec![a, b, c]);

        // Check!
        assert_eq!(newsecret.secretdata, secret.secretdata);
        println!("{:?} == {:?}", newsecret.secretdata, secret.secretdata);

    }

    #[test]
    fn test_valid_share(){
        let message = String::from("Secret message");

        let s = ShamirSecret::new(2, Some(message));
        let a = s.compute_share(1);

        assert_eq!(s.is_valid_share(a), true);

    }
}



#[derive(Debug, Clone)]
pub struct ShamirSecret {
    pub threshold: u8,
    pub secretdata: Option<String>,
    pub coefficients: Vec<Vec<u8>>
}


impl ShamirSecret {

    /// generates a new ShamirSecret struct, with randomly generated coefficients
    pub fn new(threshold: u8, secretdata: Option<String>) -> ShamirSecret {

        let mut coefficients: Vec<Vec<u8>> = vec![];

        if let Some(data) = secretdata {
            let ring_random = SystemRandom::new();
            let mut rand_bytes = [0u8, threshold - 1];

            // Secret-sharing will be applied for each byte of the secret
            for secretbyte in data.as_bytes(){

                let _ = ring_random.fill(&mut rand_bytes);
                let mut coefficient: Vec<u8> = vec![*secretbyte];
                for r in rand_bytes.iter(){
                    coefficient.push(*r);
                }
                coefficients.push(coefficient);
            }

            ShamirSecret {
                threshold: threshold,
                secretdata: Some(data.to_string()),
                coefficients: coefficients,
            }

        } else {
            // Return new Shamir Secret struct with no secretdata
            ShamirSecret {
                threshold: threshold,
                secretdata: None,
                coefficients: coefficients,
            }
        }
    }

    // TODO: check arity of share vec
    pub fn is_valid_share(&self, share: Vec<u8>) -> bool {
        if self.coefficients.len() == 0 {
            panic!("Coefficients were not initialized!");
        }

        let x: u8 = share[0];
        self.compute_share(x) == share
    }


    /// computes shares and returns a tuple representing (x, f(x))
    pub fn compute_share(&self, x: u8) -> Vec<u8> {
        if x < 1  {
            panic!("Cannot be smaller than 1 or greater than 255");
        }
        if self.coefficients.len() == 0 {
            panic!("Coefficients were not initialized!");
        }

        let mut sharebytes: Vec<u8> = vec![];

        let coefficients = self.coefficients.clone();
        for coefficient in coefficients {
            let share = _f(x, coefficient);
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
            panic!("Threshold: {} is smaller than the number of shares: {}", self.threshold, shares.len());
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

            let result_polynomial = _full_lagrange(xs.clone(), fxs);
            for coefficient in result_polynomial[..].iter() {
                mycoefficients.push(*coefficient);
            }
            mysecretdata.push(result_polynomial[0].clone());
        }
        self.coefficients = vec!(mycoefficients);
        self.secretdata = Some(String::from_utf8_lossy(&mysecretdata).to_string());
    }
}
