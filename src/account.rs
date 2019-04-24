//!
//! account.rs
//!
//! 	defines serializable Acccount object for
//!		actual user interaction with PPH db.
use serde::ser::Serializer;
use serde::de::{Deserialize, Deserializer};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountsWrapper {
	#[serde(with = "accounts")]
	pub accounts: HashMap<i64, Accounts>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Accounts {
	id: i64,
	username: String,
	salt: String,
	sharenumber: u8,
	passhash: String
}

pub mod helpers {
	use super::Accounts;

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
}
