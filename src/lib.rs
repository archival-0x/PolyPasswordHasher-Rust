//! Defines main object for secret sharing and authentication with PolyPasswordHasher.

pub mod account;
pub mod error;
pub mod math;
pub mod secretshare;

use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::randombytes;

use crate::account::Account;
use crate::error::{PPHError, PPHErrorKind, PPHResult};
use crate::secretshare::ShamirSecret;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};

// type alias to `Account`s mapping with an ID value
type Accounts = HashMap<i64, Account>;

/// main struct interface that provides the high-level abstractions for interacting with the
/// implementation to create password databases with secret sharing.
pub struct PolyPasswordHasher {
    threshold: u8,
    accounts: Accounts,
    shamirsecretobj: Option<ShamirSecret>,
    knownsecret: bool,
    saltsize: u8,
    nextavailableshare: u8,
}

impl PolyPasswordHasher {
    /// instantiates a new PolyPasswordHasher struct for interaction. It consumes a threshold number of
    /// keys, and an optional pre-existing password file. If no file is specified, a new instance
    /// will be created for use.
    pub fn new(threshold: u8, passwordfile: Option<String>) -> PPHResult<Self> {
        let mut nextavailableshare: u8 = 1;

        // if no password file is defined, initialize empty object with a randomized password key,
        // indicating a first-time setup.
        if let None = passwordfile {
            // initialize rand buffer
            let buffer = randombytes::randombytes(256);

            // creates a new shamir secret given a threshold and random buffer
            let shamirsecretobj = ShamirSecret::new(threshold, Some(buffer.clone()));

            return Ok(PolyPasswordHasher {
                threshold: threshold,
                accounts: Accounts::new(),
                shamirsecretobj: Some(shamirsecretobj),
                knownsecret: true,
                saltsize: 16u8,
                nextavailableshare: 1,
            });
        }

        let shamirsecretobj = ShamirSecret::new(threshold, None);

        // Open file and store content from passwordfile
        let mut file = File::open(passwordfile.unwrap())?;
        let mut raw_content = String::new();
        file.read_to_string(&mut raw_content)?;

        // Use serde to deserialize data from file
        let accounts: Accounts = serde_json::from_str::<Accounts>(&raw_content)?;

        // Grab the id, and the Account struct for each account within the HashMap
        for (_id, account) in accounts.iter() {
            nextavailableshare = std::cmp::max(nextavailableshare, account.sharenumber);
        }

        nextavailableshare += 1;

        Ok(Self {
            threshold,
            accounts,
            shamirsecretobj: Some(shamirsecretobj),
            knownsecret: false,
            saltsize: 16u8,
            nextavailableshare
        })
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

    /// create a new user given a set of credentials and the minimum number of shares necessary to
    /// reconstruct the original master password.
    pub fn create_account(
        &mut self,
        username: String,
        password: String,
        shares: u8,
    ) -> PPHResult<()> {
        // check if username already exists
        for (_, account) in self.accounts.iter() {
            if account.username == username {
                return Err(PPHError {
                    kind: PPHErrorKind::AuthError,
                    msg: "username already exists in database".to_string(),
                });
            }
        }

        if !self.knownsecret {
            return Err(PPHError {
                kind: PPHErrorKind::AuthError,
                msg: "password file is locked".to_string(),
            });
        }

        for sharenumber in self.nextavailableshare..(self.nextavailableshare + shares) {
            let shamirsecretdata = self
                .shamirsecretobj
                .clone()
                .unwrap()
                .compute_share(sharenumber);

            // initialize rand buffer
            let salt_buffer: Vec<u8> = randombytes::randombytes(self.saltsize as usize);

            // initialize salted password hash
            let salt: String = String::from_utf8(salt_buffer).unwrap();
            let saltpass: String = format!("{}{}", salt, password);
            let sha256::Digest(saltedpasswordhash) = sha256::hash(&saltpass.as_bytes());

            let mut passhash: Vec<u8> =
                PolyPasswordHasher::do_bytearray_xor(saltedpasswordhash.to_vec(), shamirsecretdata);
            passhash.push(saltedpasswordhash[saltedpasswordhash.len()]);

            // initialize new account entry and add to dict
            let new_account = Account {
                id: 0, // TODO: change!
                username: username.clone(),
                salt: salt,
                sharenumber: sharenumber,
                passhash: String::from_utf8(passhash).unwrap(),
            };
            self.accounts.insert(new_account.id, new_account);
        }

        // Iterate nextavailableshare
        self.nextavailableshare += shares;
        Ok(())
    }

    /// helper used to determine if a username/password can authenticate correctly
    pub fn is_valid_login(&self, username: String, password: String) -> PPHResult<bool> {
        // initial error-checking
        if !self.knownsecret {
            return Err(PPHError {
                kind: PPHErrorKind::AuthError,
                msg: "password file is locked".to_string(),
            });
        }

        // collect usernames from accounts into a vector
        let username_vec: Vec<String> = self.accounts.iter()
            .map(|(_id, acc)| acc.clone().username)
            .collect::<Vec<String>>();

        // check if username exists within the database
        if !username_vec.contains(&username) {
            return Err(PPHError {
                kind: PPHErrorKind::AuthError,
                msg: "username is not known to database".to_string(),
            });
        }

        for (_id, account) in self.accounts.iter() {
            let saltpass: String = format!("{}{}", account.salt, password);
            let sha256::Digest(saltedpasswordhash) = sha256::hash(&saltpass.as_bytes());

            if !self.knownsecret {
                let saltedcheck = saltedpasswordhash[saltedpasswordhash.len()];
                let entrycheck =
                    account.clone().passhash.into_bytes()[account.clone().passhash.len()];
                return Ok(saltedcheck == entrycheck);
            }

            let sharedata = PolyPasswordHasher::do_bytearray_xor(
                saltedpasswordhash.to_vec(),
                account.clone().passhash.into_bytes()[0..(account.clone().passhash.len())].to_vec(),
            );

            // TODO : implement thresholdless account support
            let mut share: Vec<u8> = vec![account.sharenumber];
            for element in sharedata.iter() {
                share.push(*element);
            }
            let shamir = self.shamirsecretobj.clone().unwrap();
            return Ok(shamir.is_valid_share(share));
        }
        Ok(false)
    }

    /// given the current state of the accounts stored in-memory, commit it to a persistent file
    /// for storage.
    pub fn commit(&mut self, passwordfile: String) -> PPHResult<()> {
        if self.threshold >= self.nextavailableshare {
            return Err(PPHError {
                kind: PPHErrorKind::ShardError,
                msg: "must have more shares in order to write".to_string(),
            });
        }
        let mut file = File::open(passwordfile.as_str()).unwrap();
        let raw_accounts = serde_json::to_string::<Accounts>(&self.accounts).unwrap();
        file.write_all(raw_accounts.as_bytes())?;
        Ok(())
    }

    pub fn unlock_database(&mut self, logindata: Vec<(String, String)>) -> PPHResult<()> {
        if self.knownsecret {
            return Err(PPHError {
                kind: PPHErrorKind::ShardError,
                msg: "password file is already unlocked".to_string(),
            });
        }
        let mut sharelist = vec![];

        for (username, password) in logindata {
            let mut username_vec: Vec<String> = vec![];
            for (_id, account) in self.accounts.iter() {
                username_vec.push(account.clone().username);
            }

            if !username_vec.contains(&username) {
                return Err(PPHError {
                    kind: PPHErrorKind::ShardError,
                    msg: "username is unknown to database".to_string(),
                });
            }

            for (_id, account) in self.accounts.iter() {
                if account.username == username {
                    if account.sharenumber == 0 {
                        continue;
                    }

                    // concat the salt and the password
                    let saltpass: String = format!("{}{}", account.salt, password);
                    let sha256::Digest(thissaltedpasswordhash) = sha256::hash(&saltpass.as_bytes());
                    let sharedata = PolyPasswordHasher::do_bytearray_xor(
                        thissaltedpasswordhash.to_vec(),
                        account.clone().passhash.into_bytes()[0..(account.clone().passhash.len())]
                            .to_vec(),
                    );

                    let mut thisshare = vec![account.sharenumber];
                    thisshare.extend(sharedata.iter().cloned());
                    sharelist.push(thisshare);
                }
            }
        }
        self.shamirsecretobj
            .clone()
            .unwrap()
            .recover_secretdata(sharelist);
        self.knownsecret = true;
        Ok(())
    }
}
