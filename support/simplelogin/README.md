# Real SimpleLogin integration lab

This lab builds the upstream SimpleLogin application from the commit in
`SIMPLELOGIN_COMMIT`, runs its migrations against PostgreSQL, enables its Redis
dependency, and exercises the production Bitwarden username-forwarder path.
The upstream clone is created beside the checkout by default and is never
committed to this repository.

Requirements: Docker with Compose, Git, curl, jq, Python 3, and the repository's
Rust toolchain. On ARM hosts, the upstream image runs under `linux/amd64`
emulation because that platform is fixed by SimpleLogin's Dockerfile.

```sh
# Full API/SDK/database lifecycle from a clean Docker volume
support/simplelogin/lab.sh test

# Include real SMTP forwarding and reverse-alias reply delivery through Mailpit
support/simplelogin/lab.sh test --mail

# Inspect non-secret persisted state
support/simplelogin/lab.sh inspect

# Recreate the lab with fresh database and upload volumes
support/simplelogin/lab.sh reset

# Tear down containers, network, and local database/upload volumes
support/simplelogin/lab.sh down
```

For iterative work, use `provision`, `lifecycle`, and `down` separately. The
`seed` is idempotent and does not print the newly generated API key. The
lifecycle and readiness commands capture that value internally and pass it
only in the environment of their local test process; it is not written to the
checkout or a host credentials file. `inspect` intentionally omits API key
values.

The defaults can be overridden without editing tracked files:

```sh
SIMPLELOGIN_APP_DIR=/absolute/outside/checkout/simplelogin-app \
SIMPLELOGIN_HTTP_PORT=27777 \
support/simplelogin/lab.sh test
```

The lifecycle proves create (through the actual Bitwarden generator), list,
update, alias toggle, delete, contact create/list/toggle/delete, and
reverse-alias persistence against both the real HTTP API and PostgreSQL. The
optional mail phase sends one message through SimpleLogin's email handler to a
seeded mailbox and one reply through the generated reverse alias, asserting
both deliveries in Mailpit.
