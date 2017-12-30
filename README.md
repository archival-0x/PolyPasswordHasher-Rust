# PolyPasswordHasher-Rust

Implementation of the PolyPasswordHasher password storage scheme in Rust

---

This is the Rust implementation of [PolyPasswordHasher](https://github.com/PolyPasswordHasher/PolyPasswordHasher),
a password storage scheme that prevents an attacker from cracking passwords individually.

## To run

    cargo build
    cargo test -- --nocapture

## TODO

* [ ] Write more tests for PPH library!
* [ ] Implement thresholdless support
