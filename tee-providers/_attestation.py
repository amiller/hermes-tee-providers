"""Minimal TEE attestation → hardware-bound signing key for E2EE.

Fetches a provider's attestation report, verifies the model TEE's Intel TDX quote
(via the vendored dcap-qvl verifier), checks the quote's report_data embeds our
fresh nonce and binds the signing address, and confirms the returned
signing_public_key derives to that address. The returned key is what the E2EE
transport encrypts chat content to — so only the attested enclave can read it.

Report shapes handled:
  - near-ai / redpill : GET {host}/v1/attestation/report → model_attestations[0]
                        (redpill needs Bearer auth; near-ai is public)
  - venice            : GET {base}/tee/attestation → top-level intel_quote + key

Redpill models that route via Chutes or Tinfoil expose no per-model signing key
(no E2EE) and raise a clear error rather than downgrading.

Deliberately trimmed vs. a full verifier: no measurement-anchor pinning, no GPU
NRAS check, no live TLS-cert comparison. Set TEE_ATTESTATION_VERBOSE=1 for the
underlying verifier output.
"""
import asyncio
import contextlib
import io
import os
import secrets
import sys
from pathlib import Path

import requests

_VENDOR = Path(__file__).parent / "vendor" / "nearai-cloud-verifier" / "py"
if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

_VERBOSE = os.environ.get("TEE_ATTESTATION_VERBOSE") == "1"


def _derive_eth_address(pub_hex: str) -> str:
    from eth_keys.datatypes import PublicKey
    pub = bytes.fromhex(pub_hex)
    if len(pub) == 65 and pub[0] == 0x04:
        pub = pub[1:]
    return "0x" + PublicKey(pub).to_canonical_address().hex()


def _fetch(url: str, params: dict, api_key: str) -> dict:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    r = requests.get(url, params=params, headers=headers, timeout=90)
    r.raise_for_status()
    return r.json()


def _verify_entry(att: dict, nonce: str, default_algo: str):
    """Verify one attestation entry (intel_quote + signing key); return (spk, algo)."""
    import model_verifier as mv
    quiet = contextlib.redirect_stdout(io.StringIO()) if not _VERBOSE else contextlib.nullcontext()
    with quiet:
        intel = asyncio.run(mv.check_tdx_quote(att))
        if not intel or not intel.get("verified"):
            raise RuntimeError(f"model TDX quote not verified ({intel})")
        rd = mv.check_report_data(att, nonce, intel)
    if not rd.get("embeds_nonce"):
        raise RuntimeError("report_data does not embed our nonce (stale/replayed quote)")
    if not rd.get("binds_address"):
        raise RuntimeError("report_data does not bind the signing address")
    spk = att.get("signing_public_key")
    addr = att.get("signing_address", "")
    if not spk:
        raise RuntimeError("no signing_public_key in attestation")
    algo = att.get("signing_algo", default_algo)
    if algo == "ecdsa" and addr:
        derived = _derive_eth_address(spk)
        if derived.lower() != addr.lower():
            raise RuntimeError(
                f"signing_public_key does not derive to signing_address "
                f"({derived} != {addr}) — key is not hardware-bound"
            )
    return spk, algo


def _attest_model_atts(report_url: str, model: str, algo: str, api_key: str):
    nonce = secrets.token_hex(32)
    rep = _fetch(report_url, {"model": model, "nonce": nonce,
                              "signing_algo": algo, "include_tls_fingerprint": "true"}, api_key)
    atts = rep.get("model_attestations") or []
    if not atts:
        raise RuntimeError(
            f"no model_attestations for {model!r} — this model likely routes via "
            f"Chutes or Tinfoil, which expose no per-model E2EE signing key"
        )
    return _verify_entry(atts[0], nonce, algo)


def _attest_venice(report_url: str, model: str, algo: str, api_key: str):
    nonce = secrets.token_hex(32)
    att = _fetch(report_url, {"model": model, "nonce": nonce}, api_key)
    q = att.get("intel_quote") or att.get("quote") or ""
    if isinstance(q, dict):
        q = q.get("hex") or q.get("intel_quote") or ""
    if not q:
        raise RuntimeError(f"venice: no TDX quote for {model!r} (keys: {sorted(att.keys())[:12]})")
    entry = {
        "intel_quote": q,
        "signing_public_key": att.get("signing_public_key"),
        "signing_address": att.get("signing_address", ""),
        "signing_algo": att.get("signing_algo", algo),
    }
    return _verify_entry(entry, nonce, att.get("signing_algo", algo))


def attest_signing_key(kind: str, upstream: str, model: str, api_key: str = "", signing_algo: str = "ecdsa"):
    """Return (signing_public_key_hex, signing_algo). Raise on any failure."""
    base = upstream.rstrip("/")
    if kind == "venice":
        return _attest_venice(base + "/tee/attestation", model, signing_algo, api_key)
    host = base[:-3] if base.endswith("/v1") else base
    return _attest_model_atts(host + "/v1/attestation/report", model, signing_algo, api_key)
