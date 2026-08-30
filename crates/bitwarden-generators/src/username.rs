use std::fmt;

use bitwarden_crypto::EFF_LONG_WORD_LIST;
use bitwarden_error::bitwarden_error;
use rand::{Rng, RngExt, distr::Distribution, seq::IndexedRandom};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::util::capitalize_first_letter;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum UsernameError {
    #[error("username generation failed")]
    GenerationFailed,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum AppendType {
    /// Generates a random string of 8 lowercase characters as part of your username
    Random,
    /// Uses the websitename as part of your username
    WebsiteName { website: String },
}

impl fmt::Debug for AppendType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("Random"),
            Self::WebsiteName { .. } => formatter
                .debug_struct("WebsiteName")
                .field("website", &"[REDACTED]")
                .finish(),
        }
    }
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum UsernameGeneratorRequest {
    /// Generates a single word username
    Word {
        /// Capitalize the first letter of the word
        capitalize: bool,
        /// Include a 4 digit number at the end of the word
        include_number: bool,
    },
    /// Generates an email using your provider's subaddressing capabilities.
    /// Note that not all providers support this functionality.
    /// This will generate an address of the format `youremail+generated@domain.tld`
    Subaddress {
        /// The type of subaddress to add to the base email
        r#type: AppendType,
        /// The full email address to use as the base for the subaddress
        email: String,
    },
    Catchall {
        /// The type of username to use with the catchall email domain
        r#type: AppendType,
        /// The domain to use for the catchall email address
        domain: String,
    },
}

impl fmt::Debug for UsernameGeneratorRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Word {
                capitalize,
                include_number,
            } => formatter
                .debug_struct("Word")
                .field("capitalize", capitalize)
                .field("include_number", include_number)
                .finish(),
            Self::Subaddress { r#type, .. } => formatter
                .debug_struct("Subaddress")
                .field("type", r#type)
                .field("email", &"[REDACTED]")
                .finish(),
            Self::Catchall { r#type, .. } => formatter
                .debug_struct("Catchall")
                .field("type", r#type)
                .field("domain", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Implementation of the username generator.
///
/// All username strategies are pure and local. Remote alias creation uses the explicit,
/// provider-neutral alias lifecycle service instead of embedding credentials in this request.
pub(crate) fn username(input: UsernameGeneratorRequest) -> Result<String, UsernameError> {
    use UsernameGeneratorRequest::*;
    use bitwarden_random::rng;
    match input {
        Word {
            capitalize,
            include_number,
        } => Ok(username_word(&mut rng(), capitalize, include_number)),
        Subaddress { r#type, email } => Ok(username_subaddress(&mut rng(), r#type, email)),
        Catchall { r#type, domain } => Ok(username_catchall(&mut rng(), r#type, domain)),
    }
}

fn username_word(mut rng: impl Rng, capitalize: bool, include_number: bool) -> String {
    let word = EFF_LONG_WORD_LIST
        .choose(&mut rng)
        .expect("slice is not empty");

    let mut word = if capitalize {
        capitalize_first_letter(word)
    } else {
        word.to_string()
    };

    if include_number {
        word.push_str(&random_number(&mut rng));
    }

    word
}

/// Generate a random 4 digit number, including leading zeros
fn random_number(mut rng: impl Rng) -> String {
    let num = rng.random_range(0..=9999);
    format!("{num:0>4}")
}

/// Generate a username using a plus addressed email address
/// The format is `<username>+<random-or-website>@<domain>`
fn username_subaddress(mut rng: impl Rng, r#type: AppendType, email: String) -> String {
    if email.len() < 3 {
        return email;
    }

    let (email_begin, email_end) = match email.find('@') {
        Some(pos) if pos > 0 && pos < email.len() - 1 => {
            email.split_once('@').expect("The email contains @")
        }
        _ => return email,
    };

    let email_middle = match r#type {
        AppendType::Random => random_lowercase_string(&mut rng, 8),
        AppendType::WebsiteName { website } => website,
    };

    format!("{email_begin}+{email_middle}@{email_end}")
}

/// Generate a username using a catchall email address
/// The format is `<random-or-website>@<domain>`
fn username_catchall(mut rng: impl Rng, r#type: AppendType, domain: String) -> String {
    if domain.is_empty() {
        return domain;
    }

    let email_start = match r#type {
        AppendType::Random => random_lowercase_string(&mut rng, 8),
        AppendType::WebsiteName { website } => website,
    };

    format!("{email_start}@{domain}")
}

fn random_lowercase_string(mut rng: impl Rng, length: usize) -> String {
    const LOWERCASE_ALPHANUMERICAL: &[u8] = b"abcdefghijklmnopqrstuvwxyz1234567890";
    let dist = rand::distr::slice::Choose::new(LOWERCASE_ALPHANUMERICAL).expect("Non-empty slice");

    dist.sample_iter(&mut rng)
        .take(length)
        .map(|&b| b as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    pub use super::*;

    #[test]
    fn test_username_word() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        assert_eq!(username_word(&mut rng, true, true), "Crust8369");
        assert_eq!(username_word(&mut rng, true, false), "Undertook");
        assert_eq!(username_word(&mut rng, false, true), "protector7619");
    }

    #[test]
    fn test_username_subaddress() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let user = username_subaddress(&mut rng, AppendType::Random, "demo@test.com".into());
        assert_eq!(user, "demo+g57w2ite@test.com");

        let user = username_subaddress(
            &mut rng,
            AppendType::WebsiteName {
                website: "bitwarden.com".into(),
            },
            "demo@test.com".into(),
        );
        assert_eq!(user, "demo+bitwarden.com@test.com");
    }

    #[test]
    fn test_username_catchall() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let user = username_catchall(&mut rng, AppendType::Random, "test.com".into());
        assert_eq!(user, "5ko9gye6@test.com");

        let user = username_catchall(
            &mut rng,
            AppendType::WebsiteName {
                website: "bitwarden.com".into(),
            },
            "test.com".into(),
        );
        assert_eq!(user, "bitwarden.com@test.com");
    }

    #[test]
    fn generator_request_debug_redacts_user_inputs() {
        let subaddress = UsernameGeneratorRequest::Subaddress {
            r#type: AppendType::WebsiteName {
                website: "append-hostname-that-must-not-render.example".into(),
            },
            email: "mailbox-that-must-not-render@example.test".into(),
        };
        let rendered = format!("{subaddress:?}");

        for private_value in [
            "append-hostname-that-must-not-render.example",
            "mailbox-that-must-not-render@example.test",
        ] {
            assert!(!rendered.contains(private_value));
        }
        assert!(rendered.contains("[REDACTED]"));
    }
}
