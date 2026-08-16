# Bitwarden Generators

Contains the implementation of the generators for the Bitwarden Password Manager.

First-class email alias creation is exposed by the provider-neutral `bitwarden-alias` lifecycle
service. Username generation remains pure and local; provider credentials and endpoints never
enter generated username request definitions.
