# Real SimpleLogin integration lab

This lab builds the upstream SimpleLogin application from the commit in `SIMPLELOGIN_COMMIT`, runs
its migrations against PostgreSQL, enables its Redis dependency, and exercises the production
Bitwarden username-forwarder path. The lab rewrites only the two `FROM` lines into a temporary
Dockerfile so the Node and Ubuntu bases are selected by immutable linux/amd64 manifest digests.
PostgreSQL, Redis, and Mailpit images are also digest-pinned in `compose.yml`. The upstream clone is
created beside the checkout by default and is never committed to this repository.

Requirements: Docker with Compose, Git, curl, jq, Python 3, and the repository's Rust toolchain. On
ARM hosts, the upstream image runs under `linux/amd64` emulation because that platform is fixed by
SimpleLogin's Dockerfile.

```sh
# Provision/update the lab and run the full API/SDK/database lifecycle
support/simplelogin/lab.sh test

# Include real SMTP forwarding and reverse-alias reply delivery through Mailpit
support/simplelogin/lab.sh test --mail

# Inspect non-secret persisted state
support/simplelogin/lab.sh inspect

# Show the exact upstream commit, image tag, and local image ID
support/simplelogin/lab.sh provenance

# Recreate the lab with fresh database and upload volumes
support/simplelogin/lab.sh reset

# Tear down containers, network, and local database/upload volumes
support/simplelogin/lab.sh down
```

To run any SDK, generated binding, or clean consumer against the lab without printing or persisting
its API token, provision it and use `run`. The child receives `SIMPLELOGIN_API_URL`,
`SIMPLELOGIN_API_TOKEN`, and `SIMPLELOGIN_USER_EMAIL` only in its environment:

```sh
support/simplelogin/lab.sh provision
support/simplelogin/lab.sh run -- cargo test -p bitwarden-alias --test simplelogin_live -- --ignored
support/simplelogin/lab.sh run -- npm test
```

For iterative work, use `provision`, `lifecycle`, and `down` separately. The `seed` is idempotent
and does not print the newly generated API key. The lifecycle, readiness, and `run` commands capture
that value internally and pass it only in the environment of their local test process; it is not
written to the checkout or a host credentials file, and the lab does not place it in command
arguments. `inspect` intentionally omits API key values. HTTP responses are capped at 1 MiB and the
mail checks refuse non-loopback endpoints and redirects. Seeding also removes aliases left by an
interrupted built-in lifecycle before recreating its deterministic fixtures.

The defaults can be overridden without editing tracked files:

```sh
SIMPLELOGIN_APP_DIR=/absolute/outside/checkout/simplelogin-app \
SIMPLELOGIN_HTTP_PORT=27777 \
support/simplelogin/lab.sh test
```

The lifecycle runs the real provider-neutral Bitwarden adapter and reconciliation suites, including
create, list/get, explicit enable/disable, idempotent delete, and send/reply identity management. It
then checks the corresponding service and database lifecycle directly against both the real HTTP API
and PostgreSQL. The optional mail phase sends one message through SimpleLogin's email handler to a
seeded mailbox and one reply through the generated reverse alias, asserting both deliveries in
Mailpit.

`reset` is the deterministic clean-start operation. `down` removes the containers, network,
PostgreSQL data, Redis state, and upload volume. The lifecycle also installs an exit trap so a
failed assertion or interrupted run deletes the alias and contact it created before returning.
