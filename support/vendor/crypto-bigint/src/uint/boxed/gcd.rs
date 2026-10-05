//! Support for computing greatest common divisor of two `BoxedUint`s.

use super::BoxedUint;
use crate::{Gcd, NonZero, Odd, modular::safegcd};

impl Gcd for BoxedUint {
    type Output = Self;

    /// Compute the greatest common divisor (GCD) of this number and another.
    fn gcd(&self, rhs: &Self) -> Self {
        safegcd::boxed::gcd::<false>(self, rhs)
    }

    fn gcd_vartime(&self, rhs: &Self) -> Self::Output {
        safegcd::boxed::gcd::<true>(self, rhs)
    }
}

impl Gcd<BoxedUint> for NonZero<BoxedUint> {
    type Output = NonZero<BoxedUint>;

    fn gcd(&self, rhs: &BoxedUint) -> Self::Output {
        safegcd::boxed::gcd_nz::<false>(self, rhs)
    }

    fn gcd_vartime(&self, rhs: &BoxedUint) -> Self::Output {
        safegcd::boxed::gcd_nz::<true>(self, rhs)
    }
}

impl Gcd<BoxedUint> for Odd<BoxedUint> {
    type Output = Odd<BoxedUint>;

    fn gcd(&self, rhs: &BoxedUint) -> Self::Output {
        safegcd::boxed::gcd_odd::<false>(self, rhs)
    }

    fn gcd_vartime(&self, rhs: &BoxedUint) -> Self::Output {
        safegcd::boxed::gcd_odd::<true>(self, rhs)
    }
}

#[cfg(test)]
mod tests {
    use crate::{BoxedUint, Gcd, NonZero, Odd, Resize};

    #[test]
    fn gcd_relatively_prime() {
        // Two semiprimes with no common factors
        let f = BoxedUint::from(59u32 * 67).to_odd().unwrap();
        let g = BoxedUint::from(61u32 * 71);
        let gcd = f.gcd(&g);
        assert_eq!(gcd.get(), BoxedUint::one());
    }

    #[test]
    fn gcd_nonprime() {
        let f = BoxedUint::from(4391633u32).to_odd().unwrap();
        let g = BoxedUint::from(2022161u32);
        let gcd = f.gcd(&g);
        assert_eq!(gcd.get(), BoxedUint::from(1763u32));
    }

    #[test]
    fn gcd_zero() {
        let zero = BoxedUint::from(0u32);
        let one = BoxedUint::from(1u32);

        assert_eq!(zero.gcd(&zero), zero);
        assert_eq!(zero.gcd(&one), one);
        assert_eq!(one.gcd(&zero), one);
    }

    #[test]
    fn gcd_one() {
        let f = BoxedUint::from(1u32);
        assert_eq!(BoxedUint::from(1u32), f.gcd(&BoxedUint::from(1u32)));
        assert_eq!(BoxedUint::from(1u32), f.gcd(&BoxedUint::from(2u8)));
    }

    #[test]
    fn gcd_two() {
        let f = BoxedUint::from(2u32);
        assert_eq!(f, f.gcd(&f));

        let g = BoxedUint::from(4u32);
        assert_eq!(f, f.gcd(&g));
        assert_eq!(f, g.gcd(&f));
    }

    #[test]
    fn gcd_different_sizes() {
        // Test that gcd works for boxed Uints with different numbers of limbs
        let f = BoxedUint::from(4391633u32).resize(128).to_odd().unwrap();
        let g = BoxedUint::from(2022161u32);
        let gcd = f.gcd(&g);
        assert_eq!(gcd.get(), BoxedUint::from(1763u32));
    }

    #[test]
    fn gcd_vartime_different_sizes() {
        // Test that gcd works for boxed Uints with different numbers of limbs
        let f = BoxedUint::from(4391633u32).resize(128).to_odd().unwrap();
        let g = BoxedUint::from(2022161u32);
        let gcd = f.gcd_vartime(&g);
        assert_eq!(gcd.get(), BoxedUint::from(1763u32));
    }

    macro_rules! gcd_precision_case {
        (@plain, $f:expr, $g:expr) => { $f.gcd($g) };
        (@nonzero, $f:expr, $g:expr) => {
            NonZero::new($f.clone()).unwrap().gcd($g).get()
        };
        (@odd, $f:expr, $g:expr) => {
            Odd::new($f.clone()).unwrap().gcd($g).get()
        };
        ($name:ident, $route:ident, $f:expr, $g:expr, $f_bits:expr, $g_bits:expr, $expected:expr) => {
            #[test]
            fn $name() {
                let f = BoxedUint::from($f).resize_unchecked($f_bits);
                let g = BoxedUint::from($g).resize_unchecked($g_bits);
                assert_eq!(f.bits_precision(), $f_bits);
                assert_eq!(g.bits_precision(), $g_bits);
                let result = gcd_precision_case!(@$route, f, &g);
                assert_eq!(result, BoxedUint::from($expected));
                assert_eq!(result.bits_precision(), $f_bits.max($g_bits));
            }
        };
    }
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_wide_first, plain, 4391633u32, 2022161u32, 128u32, 64u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_narrow_first, plain, 4391633u32, 2022161u32, 64u32, 128u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_equal64, plain, 4391633u32, 2022161u32, 64u32, 64u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_equal128, plain, 4391633u32, 2022161u32, 128u32, 128u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_plain_zero_nonzero_wide_first, plain, 0u32, 2022161u32, 128u32, 64u32, 2022161u32);
    gcd_precision_case!(gcd_allocated_precision_plain_zero_nonzero_narrow_first, plain, 0u32, 2022161u32, 64u32, 128u32, 2022161u32);
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_zero_wide_first, plain, 4391633u32, 0u32, 128u32, 64u32, 4391633u32);
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_zero_narrow_first, plain, 4391633u32, 0u32, 64u32, 128u32, 4391633u32);
    gcd_precision_case!(gcd_allocated_precision_plain_both_zero_wide_first, plain, 0u32, 0u32, 128u32, 64u32, 0u32);
    gcd_precision_case!(gcd_allocated_precision_plain_both_zero_narrow_first, plain, 0u32, 0u32, 64u32, 128u32, 0u32);
    gcd_precision_case!(gcd_allocated_precision_plain_both_zero_equal64, plain, 0u32, 0u32, 64u32, 64u32, 0u32);
    gcd_precision_case!(gcd_allocated_precision_plain_both_zero_equal128, plain, 0u32, 0u32, 128u32, 128u32, 0u32);
    gcd_precision_case!(gcd_allocated_precision_plain_zero_nonzero_equal64, plain, 0u32, 2022161u32, 64u32, 64u32, 2022161u32);
    gcd_precision_case!(gcd_allocated_precision_plain_nonzero_zero_equal64, plain, 4391633u32, 0u32, 64u32, 64u32, 4391633u32);
    gcd_precision_case!(gcd_allocated_precision_plain_even_wide_first, plain, 8783266u32, 4044322u32, 128u32, 64u32, 3526u32);
    gcd_precision_case!(gcd_allocated_precision_plain_even_narrow_first, plain, 8783266u32, 4044322u32, 64u32, 128u32, 3526u32);
    gcd_precision_case!(gcd_allocated_precision_nonzero_even_wide_first, nonzero, 8783266u32, 4044322u32, 128u32, 64u32, 3526u32);
    gcd_precision_case!(gcd_allocated_precision_nonzero_even_narrow_first, nonzero, 8783266u32, 4044322u32, 64u32, 128u32, 3526u32);
    gcd_precision_case!(gcd_allocated_precision_nonzero_nonzero_wide_first, nonzero, 4391633u32, 2022161u32, 128u32, 64u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_nonzero_nonzero_narrow_first, nonzero, 4391633u32, 2022161u32, 64u32, 128u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_odd_nonzero_wide_first, odd, 4391633u32, 2022161u32, 128u32, 64u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_odd_nonzero_narrow_first, odd, 4391633u32, 2022161u32, 64u32, 128u32, 1763u32);
    gcd_precision_case!(gcd_allocated_precision_nonzero_zero_wide_first, nonzero, 4391633u32, 0u32, 128u32, 64u32, 4391633u32);
    gcd_precision_case!(gcd_allocated_precision_nonzero_zero_narrow_first, nonzero, 4391633u32, 0u32, 64u32, 128u32, 4391633u32);
}
