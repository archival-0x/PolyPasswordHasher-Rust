//! account.rs
//!
//! 	Defines the serializable Acccount struct for actual user
//! 	interaction with PPH db. Support deserialization into
//!		an encapsulated wrapper HashMap.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// `AccountsWrapper` represents a serializable struct
/// for a database configuration with secret shares. It is represented
/// by a mapping between an index and an `Account`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsWrapper {
    pub accounts: HashMap<i64, Account>,
}

/// `Account` represents an account that can be committed to the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub salt: String,
    pub sharenumber: u8,
    pub passhash: String,
}
