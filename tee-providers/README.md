# tee-providers

A drop-in **model-provider plugin** that adds TEE-attested inference with
**end-to-end encryption** to a stock hermes-agent — no core changes.

Chat content is encrypted to the model enclave's *hardware-attested* signing key,
so nothing between you and the enclave (including the provider's gateway) sees
plaintext. Attestation verifies the enclave's Intel TDX quote before any key is
trusted.

Ships **NEAR AI** and **Redpill/Phala** (both E2EE-verified live). Venice is
code-complete but unregistered — see *Adding a provider*. Full docs: the
repo-level README one level up.

## Install

```bash
cp -r tee-providers "$HERMES_HOME/plugins/model-providers/tee-providers"
pip install dcap-qvl eth-keys pynacl cryptography httpx requests
export NEAR_API_KEY=...          # https://cloud.near.ai/
export REDPILL_API_KEY=...       # https://red-pill.ai/
```

Then in hermes:

```bash
hermes chat -q hi --provider near-ai --model openai/gpt-oss-120b
hermes chat -q hi --provider redpill --model phala/deepseek-chat-v3.1
```

## How it works

A `ProviderProfile` can declare a static `base_url` but cannot attach an httpx
transport or run a pre-flight check — so E2EE can't ride the normal profile
hooks. Instead the plugin runs a tiny loopback proxy and points the profile's
`base_url` at it:

```
hermes OpenAI client ──▶ 127.0.0.1:<ephemeral>/near-ai/v1 ──▶ [E2EE transport] ──▶ cloud-api.near.ai
                          (loopback only)                     encrypt/decrypt
```

- One `ThreadingHTTPServer` bound to `127.0.0.1:0` (loopback-only, ephemeral
  port, unreachable off-box). Providers are separated by URL path prefix.
- On the first chat request for a given model, the proxy **attests** that model's
  enclave (`_attestation.py`, via the vendored NEAR AI dcap-qvl verifier),
  extracts its signing key, and builds an `httpx.Client` whose transport
  (`_transport.py`) encrypts request content and decrypts the reply. Cached per
  `(provider, model)`.
- `/models` and other non-chat paths are forwarded untouched (no attestation).
- Attestation or transport failures return **502** — traffic is never silently
  downgraded to plaintext.

Import is cheap: the socket + thread start, but attestation (heavy: dcap-qvl,
network) is deferred to first use.

## What attestation checks (and what it skips)

Verifies, per request model:
1. the model enclave's Intel **TDX quote** (dcap-qvl),
2. the quote's `report_data` **embeds a fresh nonce** (not replayed) and **binds
   the signing address**,
3. the returned `signing_public_key` **derives to** that attested address — so the
   E2EE key is the hardware-bound one.

Deliberately trimmed for a minimal plugin (raise `TEE_ATTESTATION_VERBOSE=1` to
see full verifier output): no measurement-anchor pinning (expected MRTD /
compose-hash allowlist), no GPU NRAS check, no live TLS-cert comparison. Those
raise assurance from "a genuine TEE holds this key" to "the *expected* image
holds this key". Add them by extending `_attestation.py` with pinned values.

## Caveats

- **Re-attestation window** — the signing key is cached per `(provider, model)`
  for `TEE_ATTESTATION_TTL` seconds (default 3600); a key rotated inside that
  window isn't re-checked.
- **Loopback listener** — an unauthenticated HTTP server runs on `127.0.0.1`
  (ephemeral port) for the process lifetime, opened at import. It forwards the
  caller's `Authorization` header and injects nothing, so it leaks no
  credentials, but it is a local open relay while hermes runs.
- **Extra hop** — every request is re-serialized through the in-process server.
- The proxy exists only because a `ProviderProfile` can't attach a transport; a
  `wrap_transport()` hook in hermes core would remove it. See the repo README.

## Adding a provider

The proxy + E2EE transport are provider-agnostic. To add one:
1. `register_route(prefix, upstream, kind, variant, algo)` in `__init__.py` and
   register a `ProviderProfile` with `base_url` = its return value.
2. Handle that provider's report shape in `_attestation.py` (`kind` dispatches).

Notes on the others:
- **Venice** — `_attest_venice` + `VeniceE2EETransport` (distinct headers,
  04-prefixed keys) are done; just add a `register_route("venice", …,
  kind="venice", variant="venice")` block once a TEE-capable model exists.
- **Redpill Chutes/Tinfoil** — these backends expose no per-model signing key, so
  there is no E2EE to offer; `_attest_model_atts` raises a clear error for them.

## Files

| file | role |
|---|---|
| `__init__.py` | register profiles, wire routes |
| `_proxy.py` | loopback forwarder → E2EE transport |
| `_transport.py` | `E2EETransport` / `VeniceE2EETransport` (httpx) |
| `_crypto.py` | ECDSA/Ed25519 encrypt-decrypt primitives |
| `_attestation.py` | fetch report, verify TDX quote, extract signing key |
| `vendor/nearai-cloud-verifier/` | dcap-qvl-based NEAR AI verifier |
