"""tee-providers — TEE-attested inference providers with E2EE, as a drop-in plugin.

Registers TEE providers whose chat traffic is end-to-end encrypted to the model
enclave's hardware-attested signing key. No hermes core changes: each profile's
base_url points at a loopback proxy (``_proxy``) that runs attestation and E2EE
behind the scenes.

Install: copy this directory to ``$HERMES_HOME/plugins/model-providers/tee-providers/``.
Requires: dcap-qvl, eth-account, pynacl, cryptography, httpx, requests.

Ships NEAR AI and Redpill/Phala (both E2EE-verified live). Venice is code-complete
(see ``_attestation._attest_venice`` + ``VeniceE2EETransport``) but unregistered —
no current Venice model exposed TDX attestation in testing. To enable it, add a
``register_route("venice", ..., kind="venice", variant="venice")`` block below once
a TEE-capable model is available.
"""
import os

from providers import register_provider
from providers.base import ProviderProfile

from . import _proxy

# NEAR AI — public attestation endpoint, TDX, ECDSA E2EE.
_near_url = _proxy.register_route(
    "near-ai", os.environ.get("NEAR_BASE_URL", "https://cloud-api.near.ai/v1"),
    kind="near-ai", variant="near-ai", algo="ecdsa",
)
register_provider(ProviderProfile(
    name="near-ai",
    aliases=("nearai",),
    display_name="NEAR AI (TEE-attested, E2EE)",
    description="NEAR AI Cloud — TDX-attested, end-to-end encrypted to the model enclave",
    signup_url="https://cloud.near.ai/",
    env_vars=("NEAR_API_KEY",),
    base_url=_near_url,
    fallback_models=(
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "deepseek-v3.1",
        "qwen3-235b-a22b-instruct",
    ),
    default_max_tokens=16384,
))

# Redpill / Phala — same NEAR-AI report shape but Bearer-authed. Only TDX models
# with a per-model signing key get E2EE; Chutes/Tinfoil models raise a clear error.
_redpill_url = _proxy.register_route(
    "redpill", os.environ.get("REDPILL_BASE_URL", "https://api.red-pill.ai/v1"),
    kind="redpill", variant="near-ai", algo="ecdsa",
)
register_provider(ProviderProfile(
    name="redpill",
    aliases=("phala",),
    display_name="Redpill / Phala (TEE-attested, E2EE)",
    description="Redpill — TDX-attested Phala models, end-to-end encrypted to the model enclave",
    signup_url="https://red-pill.ai/",
    env_vars=("REDPILL_API_KEY",),
    base_url=_redpill_url,
    fallback_models=(
        "phala/deepseek-chat-v3.1",
        "phala/glm-4.7",
        "deepseek/deepseek-v4-flash",
        "qwen/qwen3-30b-a3b-instruct-2507",
    ),
    default_max_tokens=16384,
))
