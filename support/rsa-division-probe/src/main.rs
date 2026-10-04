use std::hint::black_box;

unsafe extern "C" {
    fn mark_secret(pointer: *mut u8, bytes: usize);
    fn release_output(pointer: *mut u8, bytes: usize);
    fn property_errors() -> usize;
    fn property_running() -> usize;
}

// Public modulus from the pinned SHA256 Wycheproof OAEP fixture. No private key is copied.
const MODULUS: &[u8; 256] = include_bytes!("public-modulus.bin");

macro_rules! check_reduction {
    ($integer:ident, $high:expr) => {{
        let modulus =
            $integer::NonZero::new($integer::BoxedUint::from_be_slice(MODULUS, 2048).unwrap())
                .unwrap();
        let mut value = if $high {
            modulus
                .as_ref()
                .wrapping_sub(&$integer::BoxedUint::one_with_precision(2048))
        } else {
            $integer::BoxedUint::zero_with_precision(2048)
        };
        let expected = value.clone();
        let words = value.as_mut_words();
        // Test-only taint starts after public key/input construction. Mark every recovered limb.
        unsafe { mark_secret(words.as_mut_ptr().cast(), std::mem::size_of_val(words)) };
        let mut output = black_box(value.rem_vartime(&modulus));
        let words = output.as_mut_words();
        // The arithmetic result is checked after explicitly authorizing this probe's output.
        unsafe { release_output(words.as_mut_ptr().cast(), std::mem::size_of_val(words)) };
        assert_eq!(output, expected);
    }};
}

fn main() {
    assert_ne!(unsafe { property_running() }, 0, "requires Valgrind");
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "expected original/candidate and zero/high");
    let high = match args[2].as_str() {
        "zero" => false,
        "high" => true,
        _ => panic!("unknown representative"),
    };
    match args[1].as_str() {
        "original" => check_reduction!(original_bigint, high),
        "candidate" => check_reduction!(candidate_bigint, high),
        _ => panic!("unknown implementation"),
    }
    println!("{} {}: {} property errors", args[1], args[2], unsafe {
        property_errors()
    });
}
