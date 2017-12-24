extern crate serde;
extern crate serde_json;
extern crate ring;

mod shamirsecret;
use shamirsecret::ShamirSecret;

use std::fs::File;

pub struct PolyPasswordHasher {
    
    // accountdict hosts a salt, sharenumber, and hash,
    // which is the salted pswd ^ secretshare
    accountdict: Option<String>,
    
    // Set this as the ShamirSecret object we will be using
    shamirsecretobj: Option<ShamirSecret>,
    
    // We want to know if the secret value is known, and if so, should
    // a password file be used?
    knownsecret: bool,
    
    // Length of salt in bytes
    saltsize: u8,
    
    // Number of bytes of data used for partial verification
    partialbytes: u8,
    
    thresholdsecretkey: Option<>,
    nextavailableshare: u8
}

impl Default for PolyPasswordHasher {
    fn default() -> PolyPasswordHasher {
            
    }
}

impl PolyPasswordHasher {
    pub fn new(threshold: u8, passwordfile: Option<String>, _partialbytes: Option<u8>) -> PolyPasswordHasher {
        if let None = passwordfile {
            
        }
        
        // If a passwordfile is specified, however...
        let secretobj = ShamirSecret::new(threshold, None);
        // No, we do not know the secret
        let knownsecret: bool = false;
        let thresholdlesskey = None;
        
        // Open file and store content from passwordfile
        let mut file = File::open(passwordfile.unwrap());
        let mut raw_content = String::new();
        file.read_to_string(&mut raw_content);
        
        let accountdict = serde_json::to_string(&raw_content).unwrap();
    
        
    }
    
    pub fn create_account(&self, username, password, shares) {
        
    }
    
    pub fn is_valid_login(&self, username, password) {
        
    }
    
    pub fn write_password_data(&self, passwordfile) {
        
    }
    
    pub fn unlock_password_data(&self, logindata) {
        
    }
    
}

/* ==============================================
   Private Math Function for XOR hashes
   ==============================================*/

fn do_bytearray_xor(a: u8, b: u8) -> Vec<u8> {
    if a.len() != b.len() {
        println!("{:?} {:?}, {:?} {:?}", a.len(), b.len(), a, b);
    }
    
    let result = vec![];
    
    for position in 0..a.len() {
        result.push(a[position] ^ b[position]);
    }
    
    result
}
