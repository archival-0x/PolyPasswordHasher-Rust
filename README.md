# PolyPasswordHasher-Rust

Implementation of the PolyPasswordHasher password storage scheme in Rust

## intro

[PolyPasswordHasher](https://pph.io) is a password storage scheme that relies upon Shamir's _(t, n)_ secret-sharing scheme. This ensures that in the case of a password database disclosure, it is near impossible to crack passwords due to the interpendency of secrets as a result of secret-sharing. Therefore, an attacker cannot crack just _one_ password hash at a time, but _all_ of them simulatenously, expontentially increasing the search space for just one password.

> To learn more, check out the original [publication](https://password-hashing.net/submissions/specs/PolyPassHash-v1.pdf).

## usage 

    cargo build
    cargo test -- --nocapture

## todos

* [ ] Documentation
* [ ] Write more tests for PPH library!
* [ ] Implement thresholdless support
