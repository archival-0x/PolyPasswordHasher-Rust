//! test_secretshare.rs
//!
//!     Tests the Shamir secret-sharing implementation,
//!     including Lagrange polynomial interpolation.

extern crate polypasswordhasher;

#[cfg(test)]
mod tests {

    use polypasswordhasher::math::polynomial;
    use polypasswordhasher::secretshare::ShamirSecret;

    // TODO: migrate to math tests
    #[test]
    fn test_full_lagrange() {
        assert_eq!(
            polynomial::full_lagrange(vec![2, 4, 5], vec![14, 30, 32]),
            vec![43, 168, 150]
        );
    }

    #[test]
    fn test_generate_secret() {
        let message = String::from("Secret message");
        let _ = ShamirSecret::new(5, Some(message));
    }

    #[test]
    fn test_recover_secret() {
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
    fn test_valid_share() {
        let message = String::from("Secret message");

        let s = ShamirSecret::new(2, Some(message));
        let a = s.compute_share(1);

        assert_eq!(s.is_valid_share(a), true);
    }
}
