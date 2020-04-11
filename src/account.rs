//! account.rs
//!
//! 	Defines the serializable Acccount struct for actual user
//! 	interaction with PPH db. Support deserialization into
//!		an encapsulated wrapper HashMap.

//use serde::ser::Serializer;
//use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountsWrapper {
    pub accounts: HashMap<i64, Accounts>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Accounts {
    pub id: i64,
    pub username: String,
    pub salt: String,
    pub sharenumber: u8,
    pub passhash: String,
}

/*
pub fn serialize<S>(map: &HashMap<i64, Accounts>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    serializer.collect_seq(map.values())
}


pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<i64, Accounts>, D::Error>
    where D: Deserializer<'de>
{
    let mut map = HashMap::new();
    for item in Vec::<Accounts>::deserialize(deserializer)? {
        map.insert(item.id, item);
    }
    Ok(map)
}
*/
