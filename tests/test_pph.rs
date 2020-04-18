//! test_pph.rs
//!
//!     Tests the main struct interface for instantiating accounts
//!     and shares.

extern crate polypasswordhasher;

#[cfg(test)]
mod tests {

    use polypasswordhasher::PolyPasswordHasher;

    #[test]
    fn test_create_pph() {
        let mut pph = PolyPasswordHasher::new(2, None, None);
        pph.create_account(String::from("admin"), String::from("correct horse"), 5);
        pph.create_account(String::from("root"), String::from("battery staple"), 5);
    }
}
