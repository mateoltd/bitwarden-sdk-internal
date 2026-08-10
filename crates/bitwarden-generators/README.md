# Bitwarden Generators

Contains the implementation of the generators for the Bitwarden Password Manager.

The optional `alias` feature is GPL-only. It routes legacy SimpleLogin forwarded-username
generation through `bitwarden-alias` and adds an identity-preserving SimpleLogin generation API.
It is deliberately opt-in so non-GPL packaging does not acquire the GPL-only alias dependency.
