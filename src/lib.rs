//!
//! lib.rs
//!
//!     Defines main object for secret
//!     sharing and authentication with
//!     PPH.

extern crate serde;
extern crate serde_json;
extern crate openssl;
extern crate ring;

#[macro_use]
extern crate serde_derive;

mod shamirsecret;
use shamirsecret::ShamirSecret;

mod account;
use account::{AccountsWrapper, Accounts};
use account::helpers;

use openssl::rand::rand_bytes;
use openssl::sha::sha256;

use std::fs::File;
use std::io::{Read, Write};
use std::collections::HashMap;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pph(){
        let mut pph = PolyPasswordHasher::new(2, None, None);
        pph.create_account(String::from("admin"), String::from("correct horse"), 5);
        pph.create_account(String::from("root"), String::from("battery staple"), 5);
    }
}


/// defines the main PolyPasswordHasher object to work with
pub struct PolyPasswordHasher {
    threshold: u8,
    accountdict: Option<AccountsWrapper>,
    shamirsecretobj: Option<ShamirSecret>,
    knownsecret: bool,
    saltsize: u8,
    partialbytes: Option<u8>,
    thresholdlesskey: Option<Vec<u8>>,
    nextavailableshare: u8
}


impl PolyPasswordHasher {

    pub fn new(threshold: u8, passwordfile: Option<String>, partialbytes: Option<u8>) -> PolyPasswordHasher {
        let mut nextavailableshare: u8 = 1;

        // if no password file is defined, initialize empty object
        if let None = passwordfile {

            // initialize rand buffer
            let mut buffer = [0u8; 256];
            rand_bytes(&mut buffer).unwrap();
            let thresholdlesskey = unsafe {
                String::from_utf8_unchecked(buffer.to_vec())
            };

            // Create new ShamirSecret object
            let shamirsecretobj = ShamirSecret::new(threshold, Some(thresholdlesskey.to_owned()));

            // Return the new struct
            return PolyPasswordHasher {
                threshold: threshold,
                accountdict: None,
                shamirsecretobj: Some(shamirsecretobj),
                knownsecret: true,
                saltsize: 16u8,
                partialbytes: partialbytes,
                thresholdlesskey: Some(thresholdlesskey.into_bytes()),
                nextavailableshare: 1
            };
        }

        let shamirsecretobj = ShamirSecret::new(threshold, None);

        // Open file and store content from passwordfile
        let mut file = File::open(passwordfile.unwrap()).unwrap();
        let mut raw_content = String::new();
        let _ = file.read_to_string(&mut raw_content);

        // Use serde to deserialize data from file
        let accountdict = serde_json::from_str::<AccountsWrapper>(&raw_content).unwrap();

        // Grab the id, and the Account struct for each account within the HashMap
        for (_id, account) in accountdict.accounts.iter() {
            nextavailableshare = std::cmp::max(nextavailableshare, account.sharenumber);
        }

        nextavailableshare += 1;

        // Finally, return the new PolyPasswordHasher struct
        PolyPasswordHasher {
            threshold: threshold,
            accountdict: Some(accountdict),
            shamirsecretobj: Some(shamirsecretobj),
            knownsecret: false,
            saltsize: 16u8,
            partialbytes: partialbytes,
            thresholdlesskey: None,
            nextavailableshare: nextavailableshare
        }
    }


    /// create a new user with credentials and number of shares to reconstruct pw
    pub fn create_account(&mut self, username: String, password: String, shares: u8) {

        // check if username already exists
        for (_, account) in accountdict.accounts.iter() {
            if account.username == username {
                panic!("username already exists");
            }
        }

        // initialize copy of accountdict
        let mut accountdict = self.accountdict.clone().unwrap();
        if self.knownsecret == false {
            panic!("password file is not unlocked");
        }


        for sharenumber in self.nextavailableshare..(self.nextavailableshare + shares) {

            let shamirsecretdata = self.shamirsecretobj.clone().unwrap().compute_share(sharenumber);

            // initialize rand buffer
            let mut salt_buffer: Vec<u8> = vec![0u8; self.saltsize as usize];
            rand_bytes(&mut salt_buffer).unwrap();

            // initialize salted password hash
            let salt: String = String::from_utf8(salt_buffer).unwrap();
            let saltpass: String = format!("{}{}", salt, password);
            let saltedpasswordhash: [u8; 32] = sha256(&saltpass.as_bytes());

            let mut passhash: Vec<u8> = do_bytearray_xor(saltedpasswordhash.to_vec(), shamirsecretdata);
            passhash.push(saltedpasswordhash[saltedpasswordhash.len() - self.partialbytes.unwrap() as usize]);

            // initialize new account entry and add to dict
            let new_account = Accounts {
                id: 0, // TODO: change!
                username: username.clone(),
                salt: salt,
                sharenumber: sharenumber,
                passhash: String::from_utf8(passhash).unwrap()
            };
            accountdict.accounts.insert(new_account.id, new_account);
        }

        // Iterate nextavailableshare
        self.nextavailableshare += shares;
    }


    /// helper used to determine if a username/password can authenticate correctly
    pub fn is_valid_login(&self, username: String, password: String) -> bool {
        let accountdict = self.accountdict.clone().unwrap();

        // initial error-checking
        if self.knownsecret == false {
            panic!("password File is not unlocked");
        }
        if self.partialbytes.unwrap() == 0 {
            panic!("partial verification is disabled");
        }

        // collect usernames
        // TODO: use iterator
        let mut username_vec: Vec<String> = vec![];
        for (_id, account) in accountdict.accounts.iter() {
            username_vec.push(account.clone().username);
        }

        if !username_vec.contains(&username){
            panic!("Unknown user {}", username);
        }

        for (_id, account) in accountdict.accounts.iter(){
             let saltpass: String = format!("{}{}", account.salt, password);
             let saltedpasswordhash: [u8; 32] = sha256(&saltpass.as_bytes());

             if !self.knownsecret {
                 let saltedcheck = saltedpasswordhash[saltedpasswordhash.len() - (self.partialbytes.unwrap() as usize)];
                 let entrycheck = account.clone().passhash.into_bytes()[account.clone().passhash.len()] - self.partialbytes.unwrap();
                 return saltedcheck == entrycheck;
             }


             let sharedata = do_bytearray_xor(saltedpasswordhash.to_vec(),
                 account.clone().passhash.into_bytes()[0..(account.clone().passhash.len() - self.partialbytes.unwrap() as usize)].to_vec());

              // TODO : implement thresholdless account support
              let mut share: Vec<u8> = vec![account.sharenumber];
              for element in sharedata.iter() {
                  share.push(*element);
              }
              let shamir = self.shamirsecretobj.clone().unwrap();
              return shamir.is_valid_share(share);
        }
        false
    }


    /// helper that writes accountdict to a file
    pub fn write_password_data(&mut self, passwordfile: String) {
        let accountdict = self.accountdict.clone().unwrap();

        if self.threshold >= self.nextavailableshare {
            panic!("Would write undecodable password file. Must have more shares before writing.");
        }

        // deserialize to file
        let mut file = File::open(passwordfile.as_str()).unwrap();
        let raw_accountdict = serde_json::to_string::<AccountsWrapper>(&accountdict).unwrap();
        let _ = file.write_all(raw_accountdict.as_bytes());
    }


    pub fn unlock_password_data(&mut self, logindata: Vec<(String, String)>) {
        let accountdict = self.accountdict.clone().unwrap();

        if self.knownsecret {
            panic!("Password File is already unlocked!");
        }
        let mut sharelist = vec![];

        for (username, password) in logindata {
            let mut username_vec: Vec<String> = vec![];
            for (_id, account) in accountdict.accounts.iter() {
                username_vec.push(account.clone().username);
            }

            if !username_vec.contains(&username){
                panic!("Unknown user {}", username);
            }

            for (_id, account) in accountdict.accounts.iter() {
                if account.username == username {
                    if account.sharenumber == 0 {
                        continue;
                    }

                    // concat the salt and the password
                    let saltpass: String = format!("{}{}", account.salt, password);
                    let thissaltedpasswordhash: [u8; 32] = sha256(&saltpass.as_bytes());
                    let sharedata = do_bytearray_xor(thissaltedpasswordhash.to_vec(),
                        account.clone().passhash.into_bytes()[0..(account.clone().passhash.len() - self.partialbytes.unwrap() as usize)].to_vec());

                    let mut thisshare = vec![account.sharenumber];
                    thisshare.extend(sharedata.iter().cloned());
                    sharelist.push(thisshare);
                }
            }
        }
        self.shamirsecretobj.clone().unwrap().recover_secretdata(sharelist);
        self.thresholdlesskey = Some(self.shamirsecretobj.clone().unwrap().secretdata.unwrap().into_bytes());
        self.knownsecret = true;
    }
}



#[inline]
fn do_bytearray_xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("{:?} {:?}, {:?} {:?}", a.len(), b.len(), a, b);
    }

    let mut result = vec![];
    for position in 0..a.len() {
        result.push(a[position] ^ b[position]);
    }
    result
}
