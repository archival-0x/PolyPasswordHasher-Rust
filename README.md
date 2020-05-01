# PolyPasswordHasher-Rust

Implementation of the PolyPasswordHasher password storage scheme in Rust

## intro

[PolyPasswordHasher](https://pph.io) is a password storage scheme that relies upon Shamir's _(t, n)_ secret-sharing scheme. This ensures that in the case of a password database disclosure, it is near impossible to crack passwords due to the interpendency of secrets as a result of secret-sharing. Therefore, an attacker cannot crack just _one_ password hash at a time, but _all_ of them simulatenously, expontentially increasing the search space for just one password.

## design

To learn more, check out the original [publication](https://password-hashing.net/submissions/specs/PolyPassHash-v1.pdf).

> TODO: API-specific design specs

## usage

To build and install locally:

```
$ cargo install --path .
```

See `tests/` to examine different use cases of the API. To run the tests:

```
$ cargo test -- --nocapture=1
```

## license

[mit](https://codemuch.tech/license.txt)
