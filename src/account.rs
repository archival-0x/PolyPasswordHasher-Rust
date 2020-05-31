//! Defines the serializable Acccount struct for actual user interaction with PPH db.

use serde::{Deserialize, Serialize};

/// `Account` represents an account that can be committed to the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub salt: String,
    pub sharenumber: u8,
    pub passhash: String,
}
