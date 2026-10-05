//! Special handling for converting the BigUint to u8 vectors

use alloc::vec::Vec;

use crypto_bigint::BoxedUint;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Returns a new vector of the given length, with 0s left padded.
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> Result<Vec<u8>> {
    // Only the fixed integer precision and requested output width select addresses
    // and copy lengths. Do not trim at a value-dependent leading-zero offset.
    let excess = input.len().saturating_sub(padded_len);
    let overflow = input[..excess].iter().fold(0u8, |acc, byte| acc | byte);
    if overflow != 0 {
        return Err(Error::InvalidPadLen);
    }

    let mut out = vec![0u8; padded_len];
    let width = core::cmp::min(input.len(), padded_len);
    out[padded_len - width..].copy_from_slice(&input[input.len() - width..]);
    Ok(out)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// Processes the full integer precision, including its leading zero bytes.
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    left_pad(&input.to_be_bytes(), padded_len)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// Processes the full integer precision, including its leading zero bytes.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let m = Zeroizing::new(input);
    let m = Zeroizing::new(m.to_be_bytes());

    left_pad(&m, padded_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_left_pad() {
        const INPUT_LEN: usize = 3;
        let input = vec![0u8; INPUT_LEN];

        // input len < padded len
        let padded = left_pad(&input, INPUT_LEN + 1).unwrap();
        assert_eq!(padded.len(), INPUT_LEN + 1);

        // input len == padded len
        let padded = left_pad(&input, INPUT_LEN).unwrap();
        assert_eq!(padded.len(), INPUT_LEN);

        // input len > padded len
        let padded = left_pad(&[1u8, 0, 0], INPUT_LEN - 1);
        assert!(padded.is_err());
    }

    #[test]
    fn fixed_width_conversion_preserves_zero_prefixes_and_overflow_errors() {
        for value in [0u32, 1, 255, 256, 65535] {
            let input = BoxedUint::from(value);
            let expected = value.to_be_bytes()[2..].to_vec();
            assert_eq!(uint_to_be_pad(input.clone(), 2).unwrap(), expected);
            assert_eq!(uint_to_zeroizing_be_pad(input, 2).unwrap(), expected);
        }
        for value in [65536u32, u32::MAX] {
            let input = BoxedUint::from(value);
            assert_eq!(uint_to_be_pad(input.clone(), 2), Err(Error::InvalidPadLen));
            assert_eq!(
                uint_to_zeroizing_be_pad(input, 2),
                Err(Error::InvalidPadLen)
            );
        }
        assert_eq!(left_pad(&[0, 0, 1], 1).unwrap(), [1]);
        assert_eq!(left_pad(&[0, 0, 0], 0).unwrap(), []);
        assert_eq!(left_pad(&[0, 1, 0], 1), Err(Error::InvalidPadLen));
    }

    #[test]
    fn fixed_width_conversion_handles_non_limb_aligned_precision() {
        let input = BoxedUint::from_be_slice(&[1, 0, 1], 17).unwrap();
        assert_eq!(uint_to_be_pad(input.clone(), 3).unwrap(), [1, 0, 1]);
        assert_eq!(uint_to_zeroizing_be_pad(input, 3).unwrap(), [1, 0, 1]);
    }
}
