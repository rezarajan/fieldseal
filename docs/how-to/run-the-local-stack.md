# Run the whole factory stack locally

This guide starts the factory, the intake app (device uploads and the results reader), the self-hosted transparency log and a local identity provider (Keycloak, passkeys only) as a compose stack, and takes a device from a passkey sign-in to a verified receipt with one command. Everything runs on your machine and nothing is pushed anywhere; the only image pulled is the pinned Keycloak.

It is a development stack. Keys are software keys in a volume (development custody), devices are unattested, and `fieldseal deployment validate` refuses the same adapters in an environment named `production` ([DEP-023](../reference/spec/deployment.md), [REG-017](../reference/spec/registration.md)). The manifest is [`examples/deployments/local-stack.yaml`](../../examples/deployments/local-stack.yaml); the compose file is [`deploy/local/compose.yaml`](../../deploy/local/compose.yaml); the entry points are the recipes in the [`justfile`](../../justfile).

## What you need

- [Nix](https://nixos.org/) with flakes, and [just](https://just.systems/). Nothing else is installed on the host: the recipes run inside the flake's dev shell, which provides the Docker client and compose, Podman and podman-compose, curl, Python with `websockets`, Chromium and shellcheck. The `fieldseal` CLI is built on demand by Nix (`tools/stack-cli.sh`) for the recipes that need it.
- A container engine daemon: Docker, or rootless Podman (which needs `newuidmap` and `newgidmap` on the host and a `/etc/subuid` entry for your user; most distributions have both).
- Linux (the images are built with Nix for Linux).

Ports used on the loopback interface: 8080 (factory), 8180 (Keycloak), 8480 (upload), 9001 (log).

The engine is `docker` by default. Choose Podman with `FIELDSEAL_CONTAINER_ENGINE=podman just up`, or `just engine=podman up`.

## 1. Start the stack

```sh
just up
```

This does, once or each time as needed:

- generates `deploy/local/.env.secrets` (git-ignored): the Keycloak admin password and the OIDC client secrets of the factory and the intake app. The manifest only names a secret (`{ secretRef: factory-oidc-client-secret }`); compose supplies the value at run time and Keycloak's realm import reads the same variable. A secret that a later release adds is appended to an existing file;
- renders `deploy/local/.generated/*.env` (git-ignored), one env file per service, with `fieldseal deployment render` ([DEP-012](../reference/spec/deployment.md)); the services read nothing else;
- builds the images with Nix and loads them into the engine: `fieldseal-factory`, `fieldseal-intake`, `fieldseal-translog` and `fieldseal-cli`;
- starts compose and waits for every endpoint.

The `init` service runs first and makes the stack's one authority, once, in the `authority` volume: a root ceremony, the publisher, builder, registration, record, receipt and receiver keys with their certificates, the log's signing key, and a trust bundle that pins the log by origin and public key. The factory, the intake app and the log all read that authority, so a device registered through the factory is the device the intake app accepts.

`just status` shows the containers and probes the endpoints; `just logs [service]` follows the logs.

## 2. Run the demo

```sh
just demo
```

The `demo` service shares Keycloak's network namespace, so `localhost:8180` is Keycloak and `localhost:8080` the factory (the only form a passkey works on), `localhost:8480` the intake app, and the log is `translog:8080`. It runs these stages and prints every command; any failure stops it with a non-zero status:

1. Publish the sample instrument through the stack's transparency log with two of three publisher signatures, prove its inclusion and verify it against the trust bundle ([PUB](../reference/spec/publishing.md)). `just seed` runs this stage alone. Publishing is idempotent: a publication's address changes with every signing, so the address of the one published is kept in the `publish` volume with the CLI state, and a repeat that can still prove it against the log prints `already published (skipped)` and leaves the log's tree size unchanged (the demo checks both).
2. Register a device. Headless Chromium with a virtual authenticator resets the `product-owner` user, registers a passkey, checks that the enrolment session is refused, signs in with the passkey, asks the portal for a registration token, and hands the token to the device: `fieldseal registration request` and `submit` against the factory. The four fingerprint words are confirmed in the portal ([REG-021](../reference/spec/registration.md)).
3. `fieldseal registration wait` until the factory has registered the device and its tenancy certificate is in `/device`.
4. Build a bundle sealed to that device and verify it the way a device does ([DIS](../reference/spec/distribution.md)).
5. Capture a scripted session on the device simulator.
6. Export the registered device's records, upload them to the intake endpoint, and verify every receipt against the trust bundle ([DEL](../reference/spec/delivery.md), [INT](../reference/spec/intake.md)).
7. Print the intake data contract and the long-format files the intake app landed in the `landing` volume.

It ends with a summary table.

## 3. Stop, restart, resume

```sh
just down      # stops the stack; keeps the registered device, the passkey and the log
just up
just resume    # the device registered before the restart is still registered, and uploads again
just purge     # forgets everything: volumes, generated files, secrets
```

All state lives in named volumes (`authority`, `factory-state`, `landing`, `log`, `device`, `clistate`, `published`, `submissions`, `keycloak-data`), so nothing is written to the repository and rootless Podman has no ownership problems: the service images own their mount points (uid 10001), which a fresh volume inherits.

## 4. By hand

The stack serves two intake listeners: `:8480` takes device uploads and `:8481` is the results reader. To read results, open `http://localhost:8481` and sign in as `product-owner` (which now has the `results-reader` role) with the passkey, as below; then download the results files.

After upgrading to a release that changes the Keycloak realm, run `just purge` first: Keycloak imports the realm only into an empty volume, and `just up` refuses to start on an older one.

Open `http://localhost:8080`, choose **Sign in** and use the username `product-owner`. The account has no passkey yet, so Keycloak asks you to register one with your browser's authenticator (a platform authenticator, a security key, or Chromium's virtual authenticator under DevTools, WebAuthn).

**This first session is deliberately not accepted for registration.** It authenticated with a username only, at the lower level of authentication, and the portal says "Your sign-in method isn't strong enough to register devices". Sign out and sign in again with the passkey: that session carries `acr=phr` and the portal accepts it ([REG-002](../reference/spec/registration.md), REG-002a). Choose the online route and **Get a registration token**; the token (it starts `FS1T:`) works once. Anyone who knows a username without a passkey can enrol one for it: that is how first enrolment works in this development realm, so do not expose the stack beyond your machine.

## How it is wired

- **Network.** The factory, the intake app and the demo share Keycloak's network namespace (`network_mode: service:keycloak`) so that the issuer URL a browser needs, `http://localhost:8180/realms/fieldseal`, is also the one the factory and the intake app reach; their ports (8080 for the factory, 8480 and 8481 for the intake app) are published on the Keycloak service. This works the same on Docker and Podman. Every published port is bound to the loopback interface.
- **Services.** The images contain only the Nix-built binary and CA certificates, run as an unprivileged user with a read-only root filesystem, no capabilities and `no-new-privileges`, and take their configuration from the environment. `GET /healthz` and `GET /readyz` on the factory, `GET /healthz` on the intake app (`:8480`; the portal on `:8481` answers `GET /`) and `GET /checkpoint` on the log are the probes; they carry no data. `fieldseal-cli` and `fieldseal-demo` (which adds curl, Python, Chromium and the demo scripts) are tool images with the same hardening.
- **Start order.** Compose uses `service_started` and `service_completed_successfully`, not `service_healthy`: rootless Podman without a systemd session never runs health checks on a timer. `just up` waits on the endpoints instead.
- **Keycloak.** `quay.io/keycloak/keycloak:26.4.7` in `start-dev` mode (H2 database in a volume), importing [`deploy/local/keycloak/fieldseal-realm.json`](../../deploy/local/keycloak/fieldseal-realm.json): realm `fieldseal`, confidential clients `fieldseal-factory` and `fieldseal-intake` (authorization code with PKCE `S256`, secret from the environment), a `roles` claim from realm roles, and the user `product-owner` with the `collector`, `operator` and `results-reader` roles and a required action to register a passkey.
- **Sign-in flow.** Username, then, for a user who has a passkey, a WebAuthn passwordless step (user verification required, resident key). Completing that step records level of authentication 2, which the realm maps to `acr` `phr`. A user without a passkey skips it, is made to register one, and ends the session at a lower level.

## Rootless Podman

`FIELDSEAL_CONTAINER_ENGINE=podman` uses Podman and podman-compose from the dev shell, with the configuration in [`deploy/local/containers/`](../../deploy/local/containers) (there is no `/etc/containers` to rely on) and a storage root of its own, `~/.local/share/fieldseal-podman`, kept apart from any other Podman data (override with `FIELDSEAL_PODMAN_HOME`). Podman runs with native rootless overlay storage; the helper binaries (conmon, crun, netavark, aardvark-dns, pasta) come from Nix. The host supplies only `newuidmap`/`newgidmap` and the `/etc/subuid` range.

## What Keycloak asserts, and what the factory does with it (REG-002a)

The factory reads authentication strength only from the ID token's own claims. For a passkey sign-in Keycloak 26.4 emits:

```json
{ "iss": "http://localhost:8180/realms/fieldseal", "aud": "fieldseal-factory", "acr": "phr", "roles": ["operator", "collector"] }
```

- **`acr`**: Keycloak has no `acr` of its own that means phishing-resistant. It reports the level of authentication the flow reached, as a number, and a realm setting (`acr.loa.map`) names the levels. This realm names level 2 `phr`, the OpenID value for phishing-resistant, which the adapter's built-in strict mapping already accepts (`phr`, `phrh`). Level 2 is recorded only when the passkey step is part of a completed sign-in, so a token without it has `acr` `0` or `1`.
- **`amr`**: Keycloak 26.4 does not emit an `amr` claim at all. The adapter therefore has nothing to read from `amr` and does not need to; it never fills the gap from configuration.
- The realm administrator controls the `acr.loa.map` and the flow, as with any identity provider. The factory trusts the realm's assertion as it would any issuer's: it is `FromProvider`, not `Asserted`, because Keycloak here is the provider itself and not a broker.

The mapping is configurable per issuer for providers whose own vocabulary differs, and strict by default: `FIELDSEAL_OIDC_PHISHING_RESISTANT_AMR` and `FIELDSEAL_OIDC_PHISHING_RESISTANT_ACR` (manifest keys `phishingResistantAmr` and `phishingResistantAcr` on the `IdentityProvider` adapter) name extra values, as comma-separated lists, that this issuer's tokens use to mean phishing-resistant. They widen only what a token may say: a token still has to carry one of the values, and with no claim there is no strength. Nothing is inferred from the issuer's name, URL or configuration. The local stack sets neither list.

## Checking it

```sh
just smoke                  # up, probes, OIDC discovery, the realm, the sign-in redirect, down
just smoke --browser        # and the whole demo in the demo container
just smoke --no-up --keep   # check a stack that is already running
```

The smoke check is opt-in: it is not part of `cargo test` and it refuses to run in CI.

## Troubleshooting

- *Sign-in says the identity provider is unavailable*: Keycloak takes up to a minute on first start. `just status`, then `just logs keycloak`.
- *A passkey you registered earlier is not offered*: the passkey lives in your authenticator and in Keycloak's volume. After `just purge` delete the old entry from your authenticator, or use a fresh browser profile.
- *Changed the realm JSON and nothing happened*: Keycloak imports it only when the realm does not exist. `just purge` and `just up`.
- *Changed the authority or the manifest*: the authority is made once. `just purge` and `just up` start from a new one.
- *Rootless Podman fails to start containers*: check that `newuidmap` and `newgidmap` are on the `PATH` with the setuid bit or file capabilities, and that `/etc/subuid` and `/etc/subgid` have a range for your user.
