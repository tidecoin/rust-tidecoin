#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//! PQClean-compatible key generation for Falcon/FN-DSA.
//!
//! This module provides deterministic key generation that is compatible
//! with the PQClean reference implementation of Falcon. It uses a 27-entry
//! u64 CDT table for Gaussian sampling and SHAKE256 directly from an
//! arbitrary-length seed, matching PQClean's algorithm rather than
//! fn-dsa's native keygen (which uses 16-bit CDT tables and a 32-byte
//! internal seed with a different PRNG).

use fn_dsa_comm::codec;
use fn_dsa_comm::mq;
use fn_dsa_comm::shake::SHAKE256;
use fn_dsa_comm::{sign_key_size, vrfy_key_size};

use crate::fxp::FXR;
use crate::ntru;

// CDT table for discrete Gaussian sampling over Z with standard
// deviation ~1.17*sqrt(q/2N) for N=1024, q=12289.
// From PQClean / falcon-rs reference.
static GAUSS_1024_12289: [u64; 27] = [
    1283868770400643928,
    6416574995475331444,
    4078260278032692663,
    2353523259288686585,
    1227179971273316331,
    575931623374121527,
    242543240509105209,
    91437049221049666,
    30799446349977173,
    9255276791179340,
    2478152334826140,
    590642893610164,
    125206034929641,
    23590435911403,
    3948334035941,
    586753615614,
    77391054539,
    9056793210,
    940121950,
    86539696,
    7062824,
    510971,
    32764,
    1862,
    94,
    4,
    0,
];

/// Extract a u64 from SHAKE256 in squeeze mode (little-endian).
fn get_rng_u64(shake: &mut SHAKE256) -> u64 {
    let mut tmp = [0u8; 8];
    shake.extract(&mut tmp);
    u64::from_le_bytes(tmp)
}

/// Generate a single Gaussian sample for degree n = 2^logn.
///
/// For each call, generates g = 1 << (10 - logn) base Gaussian samples
/// and sums them.  Each base sample uses two u64 values from the SHAKE
/// state: the first provides the sign bit and the initial CDT comparison,
/// and the second provides the remaining CDT comparisons.
fn mkgauss(shake: &mut SHAKE256, logn: u32) -> i32 {
    let g: u32 = 1u32 << (10 - logn);
    let mut val: i32 = 0;
    for _ in 0..g {
        let mut r: u64;

        // First u64: top bit is sign, remaining 63 bits compared to
        // GAUSS_1024_12289[0].
        r = get_rng_u64(shake);
        let neg: u32 = (r >> 63) as u32;
        r &= !(1u64 << 63);
        let mut f: u32 = ((r.wrapping_sub(GAUSS_1024_12289[0])) >> 63) as u32;

        // Second u64: top bit cleared, then compared against CDT entries
        // 1..27 to determine the sampled value.
        let mut v: u32 = 0;
        r = get_rng_u64(shake);
        r &= !(1u64 << 63);
        for k in 1..GAUSS_1024_12289.len() {
            let t: u32 = (((r.wrapping_sub(GAUSS_1024_12289[k])) >> 63) ^ 1) as u32;
            v |= (k as u32) & (!(t & (f ^ 1))).wrapping_add(1);
            f |= t;
        }

        // Apply sign: if neg==1, negate v.
        v = (v ^ (!neg).wrapping_add(1)).wrapping_add(neg);

        val += v as i32;
    }
    val
}

/// Generate a polynomial with Gaussian-distributed small coefficients,
/// enforcing odd parity (PQClean style).
///
/// Coefficients that fall outside [-127, +127] are rejected and resampled.
/// The parity of the sum of absolute values is tracked; if the parity is
/// even after all n coefficients, only the last coefficient is resampled
/// (PQClean convention), rather than restarting the whole polynomial.
fn poly_small_mkgauss(shake: &mut SHAKE256, logn: u32, f: &mut [i8]) {
    let n = 1usize << logn;
    let mut mod2: u32 = 0;
    let mut u = 0;
    while u < n {
        let s: i32 = mkgauss(shake, logn);

        // Reject out-of-range values.
        if s < -127 || s > 127 {
            continue;
        }

        if u == n - 1 {
            // Last coefficient: ensure odd parity.
            if (mod2 ^ (s & 1) as u32) == 0 {
                continue;
            }
        } else {
            mod2 ^= (s & 1) as u32;
        }
        f[u] = s as i8;
        u += 1;
    }
}

/// PQClean-compatible deterministic Falcon key generation.
///
/// Given a `logn` value (2..=10) and an arbitrary-length `seed`, this
/// function deterministically generates a Falcon signing key and
/// verifying key that are bit-for-bit identical to the output of the
/// PQClean reference implementation for the same seed.
///
/// Returns `true` on success, `false` if `logn` is invalid or the
/// output buffers have incorrect sizes.
///
/// # Buffer sizes
///
/// - `sign_key` must have length `sign_key_size(logn)`
/// - `vrfy_key` must have length `vrfy_key_size(logn)`
pub fn keygen_pqclean(
    logn: u32,
    seed: &[u8],
    sign_key: &mut [u8],
    vrfy_key: &mut [u8],
) -> bool {
    // Validate logn.
    if logn < 2 || logn > 10 {
        return false;
    }
    if sign_key.len() != sign_key_size(logn) {
        return false;
    }
    if vrfy_key.len() != vrfy_key_size(logn) {
        return false;
    }

    let n = 1usize << logn;

    // nbits_fg: number of bits per coefficient for f and g encoding.
    let nbits_fg: u32 = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };
    let bound = 1i32 << (nbits_fg - 1); // coefficient bound

    // Initialize SHAKE256 with seed.
    let mut shake = SHAKE256::new();
    shake.inject(seed);
    shake.flip();

    // Temporary buffers.  Sizes match what keygen_inner uses:
    //   tmp_i8:  4*n  (for f, g, F, G)
    //   tmp_u16: 2*n  (for h and scratch)
    //   tmp_u32: 6*n  (for NTRU solver)
    //   tmp_fxr: 3*n  (for ortho norm check and NTRU solver; 2.5*n rounded up)
    //
    // We allocate on-stack using arrays.  For logn=10, n=1024, this is:
    //   4*1024 = 4096 bytes for i8
    //   2*1024*2 = 4096 bytes for u16
    //   6*1024*4 = 24576 bytes for u32
    //   3*1024*8 = 24576 bytes for FXR
    // Total ~57 KB on stack, which matches the existing keygen approach.
    let mut tmp_i8 = [0i8; 4 * 1024];
    let mut tmp_u16 = [0u16; 2 * 1024];
    let mut tmp_u32 = [0u32; 6 * 1024];
    let mut tmp_fxr = [FXR::ZERO; 3 * 1024];

    let (f, rest) = tmp_i8[..4 * n].split_at_mut(n);
    let (g, rest) = rest.split_at_mut(n);
    let (cap_f, rest) = rest.split_at_mut(n);
    let (cap_g, _) = rest.split_at_mut(n);
    let (h, t16) = tmp_u16[..2 * n].split_at_mut(n);

    loop {
        // (a) Generate f and g with Gaussian sampling + odd parity.
        poly_small_mkgauss(&mut shake, logn, f);
        poly_small_mkgauss(&mut shake, logn, g);

        // (b) Check coefficient bounds.
        {
            let mut reject = false;
            for i in 0..n {
                if (f[i] as i32) >= bound
                    || (f[i] as i32) <= -bound
                    || (g[i] as i32) >= bound
                    || (g[i] as i32) <= -bound
                {
                    reject = true;
                    break;
                }
            }
            if reject {
                continue;
            }
        }

        // (c) Check squared norm: sum of f[i]^2 + g[i]^2 < 16823.
        {
            let mut sn: u32 = 0;
            for i in 0..n {
                let xf = f[i] as i32;
                let xg = g[i] as i32;
                sn = sn.wrapping_add((xf * xf + xg * xg) as u32);
            }
            if sn >= 16823 {
                continue;
            }
        }

        // (d) Check f is invertible mod q.
        if !mq::mqpoly_small_is_invertible(logn, f, t16) {
            continue;
        }

        // (e) Check orthogonal norm.
        if !ntru::check_ortho_norm(logn, f, g, &mut tmp_fxr[..(3 * n)]) {
            continue;
        }

        // (f) Solve NTRU equation to get F, G.
        if !ntru::solve_NTRU(
            logn,
            f,
            g,
            cap_f,
            cap_g,
            &mut tmp_u32[..6 * n],
            &mut tmp_fxr[..(3 * n)],
        ) {
            continue;
        }

        // (g) Compute h = g/f mod q.
        mq::mqpoly_div_small(logn, f, g, h, t16);

        // (h) Encode signing key.
        sign_key[0] = 0x50 + (logn as u8);
        let j = 1 + codec::trim_i8_encode(f, nbits_fg, &mut sign_key[1..]);
        let j = j + codec::trim_i8_encode(g, nbits_fg, &mut sign_key[j..]);
        let j = j + codec::trim_i8_encode(cap_f, 8, &mut sign_key[j..]);
        assert!(j == sign_key.len());

        // (i) Encode verifying key.
        vrfy_key[0] = 0x00 + (logn as u8);
        let j = 1 + codec::modq_encode(h, &mut vrfy_key[1..]);
        assert!(j == vrfy_key.len());

        return true;
    }
}

/// Derive a verifying (public) key from an encoded signing (private) key.
///
/// The signing key must be in the standard encoded format (header byte
/// 0x50+logn, followed by trim-encoded f, g, and F).  The verifying key
/// is written in the standard encoded format (header byte 0x00+logn,
/// followed by modq-encoded h = g/f mod q).
///
/// Returns `true` on success, `false` if the signing key is malformed
/// or the output buffer has an incorrect size.
pub fn pubkey_from_signing_key(sign_key: &[u8], vrfy_key: &mut [u8]) -> bool {
    if sign_key.is_empty() {
        return false;
    }

    // Read logn from header.
    let header = sign_key[0];
    if header < 0x52 || header > 0x5A {
        return false;
    }
    let logn = (header - 0x50) as u32;
    if logn < 2 || logn > 10 {
        return false;
    }

    // Validate signing key length.
    if sign_key.len() != sign_key_size(logn) {
        return false;
    }
    // Validate verifying key length.
    if vrfy_key.len() != vrfy_key_size(logn) {
        return false;
    }

    let n = 1usize << logn;
    let nbits_fg: u32 = match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    };

    // Decode f and g from the signing key.
    let mut f = [0i8; 1024];
    let mut g = [0i8; 1024];
    let f_slice = &mut f[..n];
    let g_slice = &mut g[..n];

    let mut offset = 1usize;

    // Decode f.
    match codec::trim_i8_decode(&sign_key[offset..], f_slice, nbits_fg) {
        Some(consumed) => offset += consumed,
        None => return false,
    }

    // Decode g.
    match codec::trim_i8_decode(&sign_key[offset..], g_slice, nbits_fg) {
        Some(consumed) => offset += consumed,
        None => return false,
    }

    // We skip F (we do not need it for pubkey derivation).
    // Just verify the remaining bytes would decode F correctly.
    // F uses 8 bits per coefficient, so it consumes n bytes.
    let f_size = n; // 8 bits per coeff, n coeffs = n bytes
    if offset + f_size != sign_key.len() {
        return false;
    }

    // Compute h = g/f mod q.
    let mut h = [0u16; 1024];
    let mut tmp = [0u16; 1024];
    let h_slice = &mut h[..n];
    let t_slice = &mut tmp[..n];
    mq::mqpoly_div_small(logn, f_slice, g_slice, h_slice, t_slice);

    // Encode verifying key.
    vrfy_key[0] = 0x00 + (logn as u8);
    let j = 1 + codec::modq_encode(h_slice, &mut vrfy_key[1..]);
    assert!(j == vrfy_key.len());

    true
}
