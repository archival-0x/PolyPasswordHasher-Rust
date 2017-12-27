extern crate serde;
extern crate serde_json;
extern crate ring;

mod shamirsecret;
use shamirsecret::ShamirSecret;

use ring::rand::{SecureRandom, SystemRandom};
use std::fs::File;
use std::io::{Read, Write};

pub struct PolyPasswordHasher {

    // Define the threshold we would need for secret sharing
    threshold: u8,
    
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
    
    // support for thresholdless encryption.
    thresholdlesskey: Option<Vec<u8>>,

    // Specifies number of used shares.
    nextavailableshare: u8
}

// TODO: write a default configuration for struct
impl Default for PolyPasswordHasher {
    fn default() -> PolyPasswordHasher {
            
    }
}

impl PolyPasswordHasher {
    pub fn new(threshold: u8, passwordfile: Option<String>, partialbytes: Option<u8>) -> PolyPasswordHasher {
        
        // Variable to hold thresholdlesskey, if available.
        let mut thresholdlesskey: Vec<u8> = vec![];

        // Variable to hold ShamirSecret object
        let mut shamirsecretobj: ShamirSecret;

        // If the user does not specify a password file...
        if let None = passwordfile {

            // Create a new array to fill with 32 random bytes
            let ring_random = SystemRandom::new();
            let mut rand_bytes = [0u8, 32];
            let _ = ring_random.fill(&mut rand_bytes);

            // Set thresholdlesskey to be equal to array as vector
            thresholdlesskey = vec![*rand_bytes];

            // Create new ShamirSecret object
            shamirsecretobj = ShamirSecret::new(threshold, Some(String::from(thresholdlesskey)));

            // Return the new struct
            return PolyPasswordHasher {
                threshold: threshold,
                accountdict: None,
                shamirsecretobj: Some(shamirsecretobj),
                knownsecret: true,
                saltsize: 16,
                partialbytes: partialbytes.unwrap(),
                thresholdlesskey: Some(thresholdlesskey),
                nextavailableshare: 1
            };

        }

        // If a passwordfile is specified, however...
        shamirsecretobj = ShamirSecret::new(threshold, None);
        
        // Open file and store content from passwordfile
        let mut file = File::open(passwordfile.unwrap()).unwrap();
        let mut raw_content = String::new();
        file.read_to_string(&mut raw_content);
        
        // Use serde to deserialize data from file
        let accountdict = serde_json::to_string(&raw_content).unwrap();

        /* TODO: Implement:

            for username in self.accountdict:
            # look at each share
            for share in self.accountdict[username]:
            self.nextavailableshare = max(self.nextavailableshare,
                                            share['sharenumber'])

        # ...then use the one after when I need a new one.
        self.nextavailableshare += 1
        
        */
    
    }
    
    pub fn create_account(&self, username: String, password: String, shares: u8) {

        // Borrow accountdict as its own variable binding
        let accountdict = self.accountdict.unwrap();

        if self.knownsecret == false {
            panic!("Password file is not unlocked!");
        }


        if accountdict.contains(&username) {
            panic!("Username already exists!");
        }

        if shares > 255 || shares < 0 {
            panic!("Invalid number of shares: {}", shares);
        }

        if shares + self.nextavailableshare > 255 {
            panic!("Would exceed maximum number of shares: {}", shares);
        }

        // TODO: implement rest

    }
    
    pub fn is_valid_login(&self, username: String, password: String) {

        // Borrow accountdict as its own variable binding
        let accountdict = self.accountdict.unwrap();

        if self.knownsecret == false && self.partialbytes == 0 {
            panic!("Password File is not unlocked and partial verification is disabled!");
        }

        if !accountdict.contains(&username) {
            panic!("Unknown username: {}", username);
        }

        // TODO: implement rest

    }
    
    pub fn write_password_data(&mut self, passwordfile: String) {
        
        // Borrow accountdict as its own variable binding
        let accountdict = self.accountdict.unwrap();

        if self.threshold >= self.nextavailableshare {
            panic!("Would write undecodable password file.   Must have more shares before writing."); 
        } 

        // Open file and store content from passwordfile
        let mut file = File::open(passwordfile.as_str()).unwrap();
        file.write_all(accountdict.as_bytes());


    }
    
    pub fn unlock_password_data(&self, logindata) {
         if self.knownsecret{
            panic!("Password File is already unlocked!");
         }
    
        let sharelist: Vec<u8> = vec![];



    }
    
}

/* ==============================================
   Private Math Function for XOR hashes
   ==============================================*/

fn do_bytearray_xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    if a.len() != b.len() {
        println!("{:?} {:?}, {:?} {:?}", a.len(), b.len(), a, b);
    }
    
    let result = vec![];
    
    for position in 0..a.len() {
        result.push(a[position] ^ b[position]);
    }
    
    result
}
