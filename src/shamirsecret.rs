use ring::rand::{SecureRandom, SystemRandom};

/// ## Introduction

/// Credit to @Nebulosus's example of Shamir Secret sharing.

/// This library was created as a supplement for the PolyPasswordHasher
/// implementation, available [here](https://github.com/PolyPasswordHasher).

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

#[derive(Debug)]
pub struct ShamirSecret {
    // This is our threshold value: number of share needed to reconstruct polynomial
    // threshold - 1 = degree of polynomial.
    pub threshold: u8,
    
    // We pass as Option monad to reinforce "optional" argument.
    // User can None to specify that no secret will be provided
    pub secretdata: Option<String>,
    
    // We generate our own vector of coefficients with Rng
    // Will not be specified by the user, as this will be randomly generated
    pub coefficients: Vec<Vec<u8>>
}

// Typedef a share (x, f(x)) as "ShamirShare"
// type ShamirShare = (u8, Vec<u8>);

impl ShamirSecret {

    // Generates a new ShamirSecret struct, with randomly generated coefficients
    // let sss: ShamirSecret = ShamirSecret::new(5, "Hello");
    pub fn new(threshold: u8, secretdata: Option<String>) -> ShamirSecret {
        
        // If user specifies a secret, create a new empty vector
        // for coefficients
        let mut coefficients: Vec<Vec<u8>> = vec![];
        
        if let Some(data) = secretdata {
            let ring_random = SystemRandom::new();
            
            // Prepare for fill(), generating random data
            // Set an array for "dest"
            let mut rand_bytes = [0u8, threshold - 1];
            
            // Secret-sharing will be applied for each byte of the secret
            for secretbyte in data.as_bytes(){
                
                // Call fill to fill rand_bytes with random data
                let _ = ring_random.fill(&mut rand_bytes);
                
                // Add secretbyte to new mutable vector
                let mut coefficient: Vec<u8> = vec![*secretbyte];
                
                // For each element in rand_byte, push it to the coefficient vector
                for r in rand_bytes.iter(){
                    coefficient.push(*r);
                }
                
                // This way, each individual byte will have a corresponding
                // pseudorandom generated coefficient.
                
                // Add coefficient to the Vector
                coefficients.push(coefficient);
            }
            // Return new ShamirSecret struct
            ShamirSecret {
                threshold: threshold,
                secretdata: Some(data.to_string()),
                coefficients: coefficients,
            }  
            
            //...otherwise  
        } else {
            // Return new Shamir Secret struct with no secretdata
            ShamirSecret {
                threshold: threshold,
                secretdata: None,
                coefficients: coefficients,
            }  
        }
    }
    
    pub fn is_valid_share(&self, share: Vec<u8>) -> bool {
        // TODO: Check arity
        
        if self.coefficients.len() == 0 {
            panic!("Coefficients were not initialized!");
        }
        
        // Assign x to first element of tuple, which is of type u8
        let x: u8 = share[0];
        
        // Get x value, compute_share, and check if equates to specified tuple
        self.compute_share(x) == share
    }

    // Computes shares and returns a tuple representing (x, f(x))
    pub fn compute_share(&self, x: u8) -> Vec<u8> {
        
        // Due to finite field, x cannot be smaller than 1 or greater than 256
        if x < 1  {
            panic!("Cannot be smaller than 1 or greater than 255");
        }
        
        // Check if we have actually generated coefficients
        if self.coefficients.len() == 0 {
            panic!("Coefficients were not initialized!");
        }
        
        let mut sharebytes: Vec<u8> = vec![];
        
        // Due to ownership and borrowship, get a clone of coefficients vector
        let coefficients = self.coefficients.clone();
        
        for coefficient in coefficients {
            
            // Compute f(x) for each value
            let share = _f(x, coefficient);
            
            sharebytes.push(share);
        }
        
        // Insert the x value at beginning of the vector
        sharebytes.insert(0, x);
        sharebytes
    }
    
    // Recover secretdata by passing vector with shares equal to threshold
    
    pub fn recover_secretdata(&mut self, shares: Vec<Vec<u8>>) {
        
        let mut newshares: Vec<Vec<u8>> = vec![];
        
        // Discards multiple same shares
        for share in shares.iter() {
            if !newshares.contains(share) {
                newshares.push(share.clone());
            }
        }
        
        let shares = newshares.clone();
        
        // Check if new shares are smaller than threshold size
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
        
        // Set coefficients
        self.coefficients = vec!(mycoefficients);
        self.secretdata = Some(String::from_utf8_lossy(&mysecretdata).to_string());
    }
}

/* ==============================================
   Private Helper Functions for Gf256
   ==============================================*/

static _GF256_EXP: [u8; 256] = [0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72,
   0x96, 0xa1, 0xf8, 0x13, 0x35, 0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73,
   0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa, 0xe5,
   0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70,
   0x90, 0xab, 0xe6, 0x31, 0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44,
   0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd, 0x4c, 0xd4,
   0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18,
   0x28, 0x78, 0x88, 0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
   0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a, 0xb5, 0xc4, 0x57,
   0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6,
   0x61, 0xa3, 0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f,
   0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0, 0xfb, 0x16, 0x3a, 0x4e,
   0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f,
   0x41, 0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed,
   0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75, 0x9f, 0xba, 0xd5, 0x64, 0xac,
   0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
   0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f,
   0xb1, 0xc8, 0x43, 0xc5, 0x54, 0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4,
   0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca, 0x45,
   0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42,
   0xc6, 0x51, 0xf3, 0x0e, 0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d,
   0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17, 0x39, 0x4b,
   0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7,
   0x52, 0xf6, 0x01];

static _GF256_LOG: [u8; 256] = [0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b,
   0x68, 0x33, 0xee, 0xdf, 0x03, 0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d,
   0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1, 0x7d,
   0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72,
   0x9a, 0xc9, 0x09, 0x78, 0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1,
   0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e, 0x96, 0x8f,
   0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40,
   0x46, 0x83, 0x38, 0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
   0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10, 0x7e, 0x6e, 0x48,
   0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85,
   0x3d, 0xba, 0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e,
   0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57, 0xaf, 0x58, 0xa8, 0x50,
   0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad,
   0xe8, 0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb,
   0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0, 0x7f, 0x0c, 0xf6, 0x6f, 0x17,
   0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
   0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1,
   0x6c, 0xaa, 0x55, 0x29, 0x9d, 0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe,
   0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1, 0x53,
   0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d,
   0x56, 0xf2, 0xd3, 0xab, 0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e,
   0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5, 0x67, 0x4a,
   0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0,
   0xf7, 0x70, 0x07];

fn _f(x: u8, coefficient_bytes: Vec<u8>) -> u8 {
    if x == 0 {
        panic!("x cannot be equal to 0");
    }
    
    let mut accumulator = 0;
    let mut x_i = 1;
    for coefficient in coefficient_bytes {
        accumulator = _gf256_add(accumulator, _gf256_mul(coefficient, x_i));
        x_i = _gf256_mul(x_i, x);
    }
    
    accumulator
}

fn _multiply_polynomials(a: Vec<u8>, b: Vec<u8>) -> Vec<u8>{
    
    // Create a vector to store results after computation
    let mut resultterms: Vec<u8> = vec![];
    
    let mut termpadding: Vec<u8> = vec![];
    
    for bterm in b {
        let mut thisvalue = termpadding.clone();
        
        for aterm in a.clone() {
            thisvalue.push(_gf256_mul(aterm, bterm));
        }
        
        resultterms = _add_polynomials(resultterms, thisvalue);
    
        termpadding.push(0);
    }
    
    resultterms
}

fn _add_polynomials(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    let mut a = a.clone();
    let mut b = b.clone();
    
    let mut result: Vec<u8> = vec![];
     
    if a.len() < b.len() {
        let mut c = vec![0; (b.len() - a.len())];
        a.append(&mut c);
    } else if a.len() > b.len() {
        let mut c = vec![0; (a.len() - b.len())];
        b.append(&mut c);
    }
    
    assert!(a.len() == b.len());
    
    for position in 0..a.len() {
        result.push(_gf256_add(a[position], b[position]));
    }
    
    result
}


pub fn _full_lagrange(xs: Vec<u8>, fxs: Vec<u8>) -> Vec<u8> {
    // Takes a vector of x's and vector of f(x)'s and computes
    // the coefficients, plus the constant (secret data)
    
    // Makes sure that they are the same length!
    assert!(xs.len() == fxs.len());
    
    let mut returnedcoefficients: Vec<u8> = vec![];

    // How to compute:
    // l_0 =  (x - x_1) / (x_0 - x_1)   *   (x - x_2) / (x_0 - x_2) * ...
    //  l_1 =  (x - x_0) / (x_1 - x_0)   *   (x - x_2) / (x_1 - x_2) * ...

    for i in 0..fxs.len() {
        
        // Set current polynomial to compute
        let mut this_polynomial: Vec<u8> = vec![1];
        
        for j in 0..fxs.len() {
            
            if i == j {
                continue;
            }
            
            let denominator = _gf256_sub(xs[i], xs[j]);
        
            let this_term = [_gf256_div(xs[j], denominator), _gf256_div(1, denominator)];
        
            this_polynomial = _multiply_polynomials(this_polynomial, this_term.to_vec());
        }
        
        this_polynomial = _multiply_polynomials(this_polynomial, [fxs[i]].to_vec());
        
        returnedcoefficients = _add_polynomials(returnedcoefficients, this_polynomial)

    }
    
    returnedcoefficients
}

fn _gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn _gf256_sub(a: u8, b: u8) -> u8 {
    _gf256_add(a, b)
}

fn _gf256_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    _GF256_EXP[((_GF256_LOG[a as usize] as u16 + _GF256_LOG[b as usize] as u16) % 255) as usize]
}

fn _gf256_div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    
    if b == 0 {
        panic!("Zero division!");
    }
    
    let a_log = _GF256_LOG[a as usize] as i16;
    let b_log = _GF256_LOG[b as usize] as i16;

    let mut diff = a_log - b_log;

    if diff < 0 {
        diff = 255 + diff;
    }
    
    _GF256_EXP[(diff % 255) as usize]
}
