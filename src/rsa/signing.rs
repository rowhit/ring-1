// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/// RSA PKCS#1 1.5 signatures.

use {bits, bssl, c, der, digest, error};
use rand;
use std;
use super::{blinding, bigint, N};
use untrusted;

/// An RSA key pair, used for signing. Feature: `rsa_signing`.
///
/// After constructing an `RSAKeyPair`, construct one or more
/// `RSASigningState`s that reference the `RSAKeyPair` and use
/// `RSASigningState::sign()` to generate signatures. See `ring::signature`'s
/// module-level documentation for an example.
pub struct RSAKeyPair {
    n: bigint::Modulus<N>,
    e: bigint::OddPositive,
    p: bigint::Modulus<P>,
    q: bigint::Modulus<Q>,
    dmp1: bigint::OddPositive,
    dmq1: bigint::OddPositive,
    iqmp: bigint::Elem<P>,

    qq: bigint::Modulus<QQ>,
    q_mod_n: bigint::Elem<N>,

    n_bits: bits::BitLength,
}

// `RSAKeyPair` is immutable. TODO: Make all the elements of `RSAKeyPair`
// implement `Sync` so that it doesn't have to do this itself.
unsafe impl Sync for RSAKeyPair {}

impl RSAKeyPair {
    /// Parse a private key in DER-encoded ASN.1 `RSAPrivateKey` form (see
    /// [RFC 3447 Appendix A.1.2]).
    ///
    /// Only two-prime keys (version 0) keys are supported. The public modulus
    /// (n) must be at least 2048 bits. Currently, the public modulus must be
    /// no larger than 4096 bits.
    ///
    /// Here's one way to generate a key in the required format using OpenSSL:
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by *ring*. PEM-encoded
    /// keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// If these commands don't work, it is likely that the private key is in a
    /// different format like PKCS#8, which isn't supported yet. An upcoming
    /// version of *ring* will likely replace the support for the
    /// `RSAPrivateKey` format with support for the PKCS#8 format.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    pub fn from_der(input: untrusted::Input)
                    -> Result<RSAKeyPair, error::Unspecified> {
        input.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let version = try!(der::small_nonnegative_integer(input));
                if version != 0 {
                    return Err(error::Unspecified);
                }
                let n = try!(bigint::Positive::from_der(input));
                let e = try!(bigint::Positive::from_der(input));
                let d = try!(bigint::Positive::from_der(input));
                let p = try!(bigint::Positive::from_der(input));
                let q = try!(bigint::Positive::from_der(input));
                let dmp1 = try!(bigint::Positive::from_der(input));
                let dmq1 = try!(bigint::Positive::from_der(input));
                let iqmp = try!(bigint::Positive::from_der(input));

                let n_bits = n.bit_length();

                // XXX: The maximum limit of 4096 bits is primarily due to lack
                // of testing of larger key sizes; see, in particular,
                // https://www.mail-archive.com/openssl-dev@openssl.org/msg44586.html
                // and
                // https://www.mail-archive.com/openssl-dev@openssl.org/msg44759.html.
                // Also, this limit might help with memory management decisions
                // later.
                let (n, e) = try!(super::check_public_modulus_and_exponent(
                    n, e, bits::BitLength::from_usize_bits(2048),
                    super::PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS));

                let d = try!(d.into_odd_positive());
                try!(bigint::verify_less_than(&e, &d));
                try!(bigint::verify_less_than(&d, &n));

                let half_n_bits = n_bits.half_rounded_up();
                if p.bit_length() != half_n_bits {
                    return Err(error::Unspecified);
                }
                let p = try!(p.into_odd_positive());
                try!(bigint::verify_less_than(&p, &d));
                if p.bit_length() != q.bit_length() {
                    return Err(error::Unspecified);
                }
                // XXX: |p < q| is actual OK, it seems, but our implementation
                // of CRT-based moduluar exponentiation used requires that
                // |q > p|. (|p == q| is just wrong.)
                let q = try!(q.into_odd_positive());
                try!(bigint::verify_less_than(&q, &p));

                let n = try!(n.into_modulus::<N>());

                // Verify that p * q == n. We restrict ourselves to modular
                // multiplication. We rely on the fact that we've verified
                // 0 < q < p < n. We check that q and p are close to sqrt(n)
                // and then assume that these preconditions are enough to
                // let us assume that checking p * q == 0 (mod n) is equivalent
                // to checking p * q == n.
                 let q_mod_n = {
                    let q = try!(q.try_clone());
                    try!(q.into_elem(&n))
                };
                let p_mod_n = {
                    let p = try!(p.try_clone());
                    try!(p.into_elem_decoded(&n))
                };
                let pq_mod_n =
                    try!(bigint::elem_mul_mixed(&q_mod_n, p_mod_n, &n));
                if !pq_mod_n.is_zero() {
                    return Err(error::Unspecified);
                }

                // XXX: We don't check that `dmp1 == d % (p - 1)` or that
                // `dmq1 == d % (q - 1)` because we don't (in the long term)
                // have a good way to do modulo with an even modulus. Instead
                // we just check that `1 <= dmp1 < p - 1` and
                // `1 <= dmq1 < q - 1`. We'll check them, to some unknown
                // extent, when we do the private key operation, since we
                // verify that the result of the private key operation using
                // the CRT parameters is consistent with `n` and `e`. TODO:
                // Either prove that what we do is sufficient, or make it so.
                //
                // We need to prove that `dmp1` < p - 1`. If we verify
                // `dmp1 < p` then we'll know that either `dmp1 == p - 1` or
                // `dmp1 < p - 1`. Since `p` is odd, `p - 1` is even. `d` is
                // odd, and an odd number modulo an even number is odd.
                // Therefore `dmp1` must be odd. But then it cannot be `p - 1`
                // and so we know `dmp1 < p - 1`.
                let dmp1 = try!(dmp1.into_odd_positive());
                try!(bigint::verify_less_than(&dmp1, &p));
                // The same argument can be used to prove `dmq1 < q - 1`.
                let dmq1 = try!(dmq1.into_odd_positive());
                try!(bigint::verify_less_than(&dmq1, &q));

                let p = try!(p.into_modulus::<P>());

                let iqmp = try!(iqmp.into_elem(&p));
                let q_mod_p = {
                    let q = try!(q.try_clone());
                    try!(q.into_elem_decoded(&p))
                };
                let iqmp_times_q_mod_p =
                    try!(bigint::elem_mul_mixed(&iqmp, q_mod_p, &p));
                if !iqmp_times_q_mod_p.is_one() {
                    return Err(error::Unspecified);
                }

                let q_mod_n_decoded = {
                    let q = try!(q.try_clone());
                    try!(q.into_elem_decoded(&n))
                };
                let qq =
                    try!(bigint::elem_mul_mixed(&q_mod_n, q_mod_n_decoded,
                                                &n));
                let qq = try!(qq.into_odd_positive());
                let qq = try!(qq.into_modulus::<QQ>());

                let q = try!(q.into_modulus::<Q>());

                Ok(RSAKeyPair {
                    n: n,
                    e: e,
                    p: p,
                    q: q,
                    dmp1: dmp1,
                    dmq1: dmq1,
                    iqmp: iqmp,
                    q_mod_n: q_mod_n,
                    qq: qq,
                    n_bits: n_bits,
                })
            })
        })
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    pub fn public_modulus_len(&self) -> usize {
        self.n_bits.as_usize_bytes_rounded_up()
    }
}


enum P {}
unsafe impl bigint::Field for P {}

enum Q {}
unsafe impl bigint::Field for Q {}

enum QQ {}
unsafe impl bigint::Field for QQ {}


/// Needs to be kept in sync with `struct rsa_st` (in `include/openssl/rsa.h`).
#[repr(C)]
struct RSA<'a> {
    e: &'a bigint::BIGNUM,
    dmp1: &'a bigint::BIGNUM,
    dmq1: &'a bigint::BIGNUM,
    mont_n: &'a bigint::BN_MONT_CTX,
    mont_p: &'a bigint::BN_MONT_CTX,
    mont_q: &'a bigint::BN_MONT_CTX,
    mont_qq: &'a bigint::BN_MONT_CTX,
    qmn_mont: &'a bigint::BIGNUM,
    iqmp_mont: &'a bigint::BIGNUM,
}


/// State used for RSA Signing. Feature: `rsa_signing`.
///
/// # Performance Considerations
///
/// Every time `sign` is called, some internal state is updated. Usually the
/// state update is relatively cheap, but the first time, and periodically, a
/// relatively expensive computation (computing the modular inverse of a random
/// number modulo the public key modulus, for blinding the RSA exponentiation)
/// will be done. Reusing the same `RSASigningState` when generating multiple
/// signatures improves the computational efficiency of signing by minimizing
/// the frequency of the expensive computations.
///
/// `RSASigningState` is not `Sync`; i.e. concurrent use of an `sign()` on the
/// same `RSASigningState` from multiple threads is not allowed. An
/// `RSASigningState` can be wrapped in a `Mutex` to be shared between threads;
/// this would maximize the computational efficiency (as explained above) and
/// minimizes memory usage, but it also minimizes concurrency because all the
/// calls to `sign()` would be serialized. To increases concurrency one could
/// create multiple `RSASigningState`s that share the same `RSAKeyPair`; the
/// number of `RSASigningState` in use at once determines the concurrency
/// factor. This increases memory usage, but only by a small amount, as each
/// `RSASigningState` is much smaller than the `RSAKeyPair` that they would
/// share. Using multiple `RSASigningState` per `RSAKeyPair` may also decrease
/// computational efficiency by increasing the frequency of the expensive
/// modular inversions; managing a pool of `RSASigningState`s in a
/// most-recently-used fashion would improve the computational efficiency.
pub struct RSASigningState {
    key_pair: std::sync::Arc<RSAKeyPair>,
    blinding: blinding::Blinding,
}

impl RSASigningState {
    /// Construct an `RSASigningState` for the given `RSAKeyPair`.
    pub fn new(key_pair: std::sync::Arc<RSAKeyPair>)
               -> Result<Self, error::Unspecified> {
        Ok(RSASigningState {
            key_pair: key_pair,
            blinding: blinding::Blinding::new(),
        })
    }

    /// The `RSAKeyPair`. This can be used, for example, to access the key
    /// pair's public key through the `RSASigningState`.
    pub fn key_pair(&self) -> &RSAKeyPair { self.key_pair.as_ref() }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` is used for blinding the message during
    /// signing, to mitigate some side-channel (e.g. timing) attacks.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly. To help mitigate the current
    /// imperfections, and for defense-in-depth, base blinding is always done.
    /// Exponent blinding is not done, but it may be done in the future.
    #[allow(non_shorthand_field_patterns)] // Work around compiler bug.
    pub fn sign(&mut self, padding_alg: &'static ::signature::RSAEncoding,
                rng: &rand::SecureRandom, msg: &[u8], signature: &mut [u8])
                -> Result<(), error::Unspecified> {
        let mod_bits = self.key_pair.n_bits;
        if signature.len() != mod_bits.as_usize_bytes_rounded_up() {
            return Err(error::Unspecified);
        }

        let &mut RSASigningState {
            key_pair: ref key,
            blinding: ref mut blinding,
        } = self;

        let rsa =  RSA {
            e: key.e.as_ref(),
            dmp1: key.dmp1.as_ref(),
            dmq1: key.dmq1.as_ref(),
            mont_n: key.n.as_ref(),
            mont_p: key.p.as_ref(),
            mont_q: key.q.as_ref(),
            mont_qq: key.qq.as_ref(),
            qmn_mont: key.q_mod_n.as_ref_montgomery_encoded(),
            iqmp_mont: key.iqmp.as_ref_montgomery_encoded(),
        };

        let m_hash = digest::digest(padding_alg.digest_alg(), msg);
        try!(padding_alg.encode(&m_hash, signature, mod_bits, rng));
        // TODO: Avoid having `encode()` pad its output, and then remove
        // `Positive::from_be_bytes_padded()`.
        let base = try!(bigint::Positive::from_be_bytes_padded(
            untrusted::Input::from(signature)));
        let base = try!(base.into_elem_decoded(&key.n));

        let base = try!(blinding.blind(base, &key.e, &key.n, rng, |mut base| {
            try!(bssl::map_result(unsafe {
                GFp_rsa_private_transform(&rsa, base.as_mut_ref())
            }));
            Ok(base)
        }));

        base.fill_be_bytes(signature)
    }
}


#[allow(improper_ctypes)]
extern {
    fn GFp_rsa_private_transform(rsa: &RSA, base: &mut bigint::BIGNUM)
                                 -> c::int;
}


#[cfg(test)]
mod tests {
    // We intentionally avoid `use super::*` so that we are sure to use only
    // the public API; this ensures that enough of the API is public.
    use {error, rand, signature, test};
    use std;
    use super::super::blinding;
    use untrusted;

    #[test]
    fn test_signature_rsa_pkcs1_sign() {
        let rng = rand::SystemRandom::new();
        test::from_file("src/rsa/rsa_pkcs1_sign_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PKCS1_SHA256,
                "SHA384" => &signature::RSA_PKCS1_SHA384,
                "SHA512" => &signature::RSA_PKCS1_SHA512,
                _ =>  { panic!("Unsupported digest: {}", digest_name) }
            };

            let private_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let private_key = untrusted::Input::from(&private_key);
            let key_pair = signature::RSAKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let key_pair = std::sync::Arc::new(key_pair);

            // XXX: This test is too slow on Android ARM Travis CI builds.
            // TODO: re-enable these tests on Android ARM.
            let mut signing_state =
                signature::RSASigningState::new(key_pair).unwrap();
            let mut actual: std::vec::Vec<u8> =
                vec![0; signing_state.key_pair().public_modulus_len()];
            signing_state.sign(alg, &rng, &msg, actual.as_mut_slice()).unwrap();
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        });
    }



    // `RSAKeyPair::sign` requires that the output buffer is the same length as
    // the public key modulus. Test what happens when it isn't the same length.
    #[test]
    fn test_signature_rsa_pkcs1_sign_output_buffer_len() {
        // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
        // SHA256 digest algorithm.
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();

        // The output buffer is one byte too short.
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len() - 1];

        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());

        // The output buffer is the right length.
        signature.push(0);
        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_ok());


        // The output buffer is one byte too long.
        signature.push(0);
        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());
    }

    // Once the `BN_BLINDING` in an `RSAKeyPair` has been used
    // `GFp_BN_BLINDING_COUNTER` times, a new blinding should be created. we
    // don't check that a new blinding was created; we just make sure to
    // exercise the code path, so this is basically a coverage test.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_reuse() {
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signature = vec![0; key_pair.public_modulus_len()];

        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();

        for _ in 0..(blinding::REMAINING_MAX + 1) {
            let prev_remaining = signing_state.blinding.remaining();
            let _ = signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng,
                                       MESSAGE, &mut signature);
            let remaining = signing_state.blinding.remaining();
            assert_eq!((remaining + 1) % blinding::REMAINING_MAX,
                       prev_remaining);
        }
    }

    // In `crypto/rsa/blinding.c`, when `bn_blinding_create_param` fails to
    // randomly generate an invertible blinding factor too many times in a
    // loop, it returns an error. Check that we observe this.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_creation_failure() {
        const MESSAGE: &'static [u8] = b"hello, world";

        // Stub RNG that is constantly 0. In `bn_blinding_create_param`, this
        // causes the candidate blinding factors to always be 0, which has no
        // inverse, so `BN_mod_inverse_no_branch` fails.
        let rng = test::rand::FixedByteRandom { byte: 0x00 };

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len()];
        let result = signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng,
                                        MESSAGE, &mut signature);

        assert!(result.is_err());
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_signature_rsa_pss_sign() {
        // Outputs the same value whenever a certain length is requested (the
        // same as the length of the salt). Otherwise, the rng is used.
        struct DeterministicSalt<'a> {
            salt: &'a [u8],
            rng: &'a rand::SecureRandom
        }
        impl<'a> rand::SecureRandom for DeterministicSalt<'a> {
            fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
                let dest_len = dest.len();
                if dest_len != self.salt.len() {
                    try!(self.rng.fill(dest));
                } else {
                    dest.copy_from_slice(&self.salt);
                }
                Ok(())
            }
        }
        let rng = rand::SystemRandom::new();

        test::from_file("src/rsa/rsa_pss_sign_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_SHA256,
                "SHA384" => &signature::RSA_PSS_SHA384,
                "SHA512" => &signature::RSA_PSS_SHA512,
                _ =>  { panic!("Unsupported digest: {}", digest_name) }
            };

            let result = test_case.consume_string("Result");
            let private_key = test_case.consume_bytes("Key");
            let private_key = untrusted::Input::from(&private_key);
            let key_pair = signature::RSAKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let key_pair = std::sync::Arc::new(key_pair);
            let msg = test_case.consume_bytes("Msg");
            let salt = test_case.consume_bytes("Salt");
            let expected = test_case.consume_bytes("Sig");

            let new_rng = DeterministicSalt { salt: &salt, rng: &rng };

            let mut signing_state =
                signature::RSASigningState::new(key_pair).unwrap();
            let mut actual: std::vec::Vec<u8> =
                vec![0; signing_state.key_pair().public_modulus_len()];
            try!(signing_state.sign(alg, &new_rng, &msg, actual.as_mut_slice()));
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        });
    }


    #[test]
    fn test_sync_and_send() {
        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);

        let _: &Send = &key_pair;
        let _: &Sync = &key_pair;

        let signing_state = signature::RSASigningState::new(key_pair).unwrap();
        let _: &Send = &signing_state;
        // TODO: Test that signing_state is NOT Sync; i.e.
        // `let _: &Sync = &signing_state;` must fail
    }
}
