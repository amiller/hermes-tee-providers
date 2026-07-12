# hermes-tee-providers

A drop-in [Hermes Agent](https://github.com/NousResearch/hermes-agent)
**model-provider plugin** that adds TEE-attested inference with **end-to-end
encryption** — no changes to hermes core.

Chat content is encrypted to the model enclave's *hardware-attested* signing key,
so nothing between you and the enclave (including the provider's own gateway) sees
plaintext. The enclave's Intel TDX quote is verified before any key is trusted.

## Providers

| Provider | Status | Notes |
|---|---|---|
| **NEAR AI** | ✅ live E2EE | `openai/gpt-oss-120b`, `openai/gpt-oss-20b`, … Public attestation endpoint. |
| **Redpill / Phala** | ✅ live E2EE | TDX models only: `phala/deepseek-chat-v3.1`, `phala/glm-4.7`, `deepseek/deepseek-v4-flash`, … |
| Redpill → Chutes / Tinfoil | ⛔ no E2EE | These backends expose no per-model signing key. The plugin **errors clearly** rather than sending plaintext. |
| **Venice** | 🟡 code-complete, unregistered | Adapter + transport implemented; no current Venice model exposed TDX attestation in testing. Enable in `__init__.py` once one does. |

## Install

```bash
git clone https://github.com/amiller/hermes-tee-providers
cp -r hermes-tee-providers/tee-providers "$HERMES_HOME/plugins/model-providers/tee-providers"
pip install -r hermes-tee-providers/requirements.txt

export NEAR_API_KEY=...       # https://cloud.near.ai/
export REDPILL_API_KEY=...    # https://red-pill.ai/
```

Then in hermes:

```bash
hermes chat -q "hello" --provider near-ai --model openai/gpt-oss-120b
hermes chat -q "hello" --provider redpill --model phala/deepseek-chat-v3.1
```

## How it works

A hermes `ProviderProfile` can declare a static `base_url` but cannot attach an
httpx transport or run a pre-flight check — so E2EE can't ride the normal profile
hooks. Instead the plugin runs a tiny loopback proxy and points each profile's
`base_url` at it:

```
hermes OpenAI client ─▶ 127.0.0.1:<ephemeral>/<provider>/v1 ─▶ [E2EE transport] ─▶ real upstream
                        (loopback only)                        encrypt / decrypt
```

- One `ThreadingHTTPServer` bound to `127.0.0.1:0` — loopback-only, ephemeral
  port, unreachable off-box. Providers are separated by URL path prefix.
- On the first chat for a given model, the proxy **attests** that model's enclave,
  extracts its signing key, and builds an `httpx` transport that encrypts request
  content and decrypts the reply. Cached per `(provider, model)` — the signing key
  is per-model, since each model runs in its own enclave.
- `/models` and other non-chat paths are forwarded untouched (no attestation).
- Attestation or transport failures return **502** — traffic is never silently
  downgraded to plaintext.

Because the E2EE transport already passes non-chat requests through and each
profile just points at the loopback URL, this needs **zero** hermes core changes:
`auth.py` auto-registers plugin profiles into `PROVIDER_REGISTRY`, and runtime
resolution reads the loopback `base_url` from there.

## What attestation checks (and what it skips)

Per request model, before trusting the E2EE key:

1. the model enclave's Intel **TDX quote** (local dcap-qvl verification),
2. the quote's `report_data` **embeds a fresh nonce** (not replayed) and **binds
   the signing address**,
3. the returned `signing_public_key` **derives to** that attested address — so the
   key you encrypt to is the hardware-bound one.

Deliberately trimmed for a minimal plugin (set `TEE_ATTESTATION_VERBOSE=1` for
full verifier output): no measurement-anchor pinning (expected MRTD / compose-hash
allowlist), no GPU NRAS check, no live TLS-cert comparison. Those raise assurance
from "a genuine TEE holds this key" to "the *expected* image holds this key". Add
them by extending `tee-providers/_attestation.py` with pinned values.

## Layout

```
tee-providers/            the drop-in plugin (copy this into your plugins dir)
  __init__.py             register profiles, wire routes
  _proxy.py               loopback forwarder → E2EE transport
  _transport.py           E2EETransport / VeniceE2EETransport (httpx)
  _crypto.py              ECDSA/Ed25519 encrypt-decrypt primitives
  _attestation.py         fetch report, verify TDX quote, extract signing key
  vendor/nearai-cloud-verifier/   dcap-qvl-based verifier (MIT, vendored)
requirements.txt
```

## License

MIT. Vendored `nearai-cloud-verifier` is MIT (© 2025 nearai-cloud).
