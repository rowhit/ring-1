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

//! RSA base blinding.
//!
//! This is based on the suggestions in the paper
//! "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other
//! Systems" by Paul C. Kocher.

use {error, rand};
use core;
use super::{bigint, N};

pub struct Blinding(Option<Contents>);

struct Contents {
    blinding_factor: bigint::Elem<N>, // `(1 / v_i)**e` from the paper.
    blinding_factor_inv: bigint::Elem<N>, // `v_f` from the paper.
    remaining: usize,
}

impl Blinding {
    pub fn new() -> Self { Blinding(None) }

    pub fn blind<F>(&mut self, x: bigint::ElemDecoded<N>,
                    e: &bigint::OddPositive, n: &bigint::Modulus<N>,
                    rng: &rand::SecureRandom, f: F)
                    -> Result<bigint::ElemDecoded<N>, error::Unspecified>
                    where F: FnOnce(bigint::ElemDecoded<N>)
                                    -> Result<bigint::ElemDecoded<N>,
                                              error::Unspecified> {
        let old_contents = core::mem::replace(&mut self.0, None);

        let new_contents = try!(match old_contents {
            Some(Contents {
                blinding_factor,
                blinding_factor_inv,
                remaining,
            }) => {
                if remaining > 0 {
                    // Update the existing blinding factor by squaring it, as
                    // suggested in the paper.
                    let blinding_factor =
                        try!(bigint::elem_squared(blinding_factor, n));
                    let blinding_factor_inv =
                        try!(bigint::elem_squared(blinding_factor_inv, n));
                    Ok(Contents {
                        blinding_factor: blinding_factor,
                        blinding_factor_inv: blinding_factor_inv,
                        remaining: remaining - 1,
                    })
                } else {
                    // Create a new, independent blinding factor.
                    reset(blinding_factor, blinding_factor_inv, e, n, rng)
                }
            },

            None => {
                let elem1 = try!(bigint::Elem::zero());
                let elem2 = try!(bigint::Elem::zero());
                reset(elem1, elem2, e, n, rng)
            },
        });

        // Blind `x`.
        let x =
            try!(bigint::elem_mul_mixed(&new_contents.blinding_factor, x, n));

        let x = try!(f(x));

        // Unblind `x`.
        let x =
            try!(bigint::elem_mul_mixed(&new_contents.blinding_factor_inv, x,
                                        n));

        let _ = core::mem::replace(&mut self.0, Some(new_contents));

        Ok(x)
    }

    #[cfg(test)]
    pub fn remaining(&self) -> usize {
        match &self.0 {
            &Some(Contents { remaining, .. }) => remaining,
            &None => { 0 },
        }
    }
}

fn reset(arbitrary1: bigint::Elem<N>, arbitrary2: bigint::Elem<N>,
         e: &bigint::OddPositive, n: &bigint::Modulus<N>,
         rng: &rand::SecureRandom) -> Result<Contents, error::Unspecified> {
    // Use `into_elem_decoded_montgomery_encoded` to grab the underling
    // `BIGNUM` to avoid a superfluous `malloc()` & `free()`.
    let mut random = arbitrary1.into_elem_decoded_montgomery_encoded();
    let mut random_inv = arbitrary2.into_elem_decoded_montgomery_encoded();

    for _ in 0..32 {
        try!(bigint::elem_randomize(&mut random, n, rng));
        match bigint::elem_set_to_inverse_blinded(&mut random_inv, &random, n,
                                                  rng) {
            Ok(()) => {
                let random = try!(bigint::elem_exp_vartime(random, e, n));
                let random = try!(random.into_elem(n));
                let random_inv = try!(random_inv.into_elem(n));
                return Ok(Contents {
                    blinding_factor: random,
                    blinding_factor_inv: random_inv,
                    remaining: REMAINING_MAX - 1,
                });
            },
            Err(bigint::InversionError::NoInverse) => {}, // continue
            Err(_) => { return Err(error::Unspecified); }
        }
    }

    Err(error::Unspecified)
}

// This must never be zero. XXX: We use the value 32 because OpenSSL does, but
// we have no logical justification for this choice. TODO: Figure out a better
// value and/or a better reason for the value.
pub const REMAINING_MAX: usize = 32;

#[cfg(test)]
mod tests {
    // Testing for this module is done as part of the ring::rsa::signing tests.
}
