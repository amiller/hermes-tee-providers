"""Minimal loopback E2EE proxy.

A ProviderProfile can set a static base_url but cannot attach an httpx transport,
so E2EE for a stock hermes-agent has to happen behind a URL. This binds one
``127.0.0.1:0`` server (loopback-only, ephemeral port — unreachable off-box) and
routes providers by path prefix (``/near-ai/v1`` …). Chat requests are replayed
through ``httpx.Client(transport=E2EETransport(signing_key))`` pointed at the
real upstream; the transport encrypts content and decrypts the reply. Every
other path (model listing, etc.) is forwarded untouched.

The model's signing key is per-model — each model runs in its own enclave — so
attestation keys off the model named in the request, cached per (provider, model).
"""
import http.server
import json
import threading
from urllib.parse import urlsplit

import httpx

_ROUTES: dict[str, dict] = {}                    # prefix -> {root, upstream, kind, variant, algo}
_E2EE: dict[tuple, httpx.BaseTransport] = {}     # (prefix, model) -> E2EE transport
_PLAIN = httpx.HTTPTransport()                   # shared passthrough for non-chat paths
_LOCK = threading.Lock()
_server = None
_port = None

_HOP_BY_HOP = {"host", "content-length", "connection", "keep-alive",
               "transfer-encoding", "proxy-connection", "te", "trailer", "upgrade"}


def register_route(prefix: str, upstream: str, kind: str, variant: str, algo: str = "ecdsa") -> str:
    """Register a provider and return the loopback base_url its profile should use."""
    parts = urlsplit(upstream)
    path = parts.path.rstrip("/")
    _ROUTES[prefix] = {
        "root": f"{parts.scheme}://{parts.netloc}",
        "upstream": f"{parts.scheme}://{parts.netloc}{path}",
        "kind": kind,
        "variant": variant,
        "algo": algo,
    }
    return f"http://127.0.0.1:{start()}/{prefix}{path}"


def _e2ee_transport_for(prefix: str, model: str, api_key: str) -> httpx.BaseTransport:
    key = (prefix, model)
    with _LOCK:
        t = _E2EE.get(key)
        if t is not None:
            return t
        route = _ROUTES[prefix]
        from ._attestation import attest_signing_key
        from ._transport import E2EETransport, VeniceE2EETransport
        spk, algo = attest_signing_key(route["kind"], route["upstream"], model, api_key, route["algo"])
        cls = VeniceE2EETransport if route["variant"] == "venice" else E2EETransport
        t = cls(spk, algo, inner=httpx.HTTPTransport())
        _E2EE[key] = t
        return t


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _forward(self):
        segs = self.path.split("/", 2)
        prefix = segs[1] if len(segs) > 1 else ""
        subpath = "/" + (segs[2] if len(segs) > 2 else "")
        if prefix not in _ROUTES:
            self.send_error(404, f"unknown provider route {prefix!r}")
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}

        # Resolve transport before writing any bytes, so an attestation failure
        # surfaces as a clean 502 rather than a truncated stream.
        try:
            if subpath.endswith("/chat/completions"):
                model = json.loads(body or b"{}").get("model", "")
                auth = self.headers.get("Authorization", "")
                api_key = auth[7:] if auth.lower().startswith("bearer ") else ""
                transport = _e2ee_transport_for(prefix, model, api_key)
            else:
                transport = _PLAIN
        except Exception as exc:
            # Propagate — never silently fall back to unencrypted transport.
            self.send_error(502, f"E2EE proxy error: {exc}")
            return

        req = httpx.Request(self.command, _ROUTES[prefix]["root"] + subpath,
                            headers=headers, content=body)
        resp = transport.handle_request(req)
        try:
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() in _HOP_BY_HOP:
                    continue
                self.send_header(k, v)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in resp.stream:
                if chunk:
                    self.wfile.write(b"%X\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.write(b"0\r\n\r\n")
        finally:
            resp.close()

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_DELETE = _forward


def start() -> int:
    """Start the loopback server once; return its port."""
    global _server, _port
    with _LOCK:
        if _port is not None:
            return _port
        _server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        _server.daemon_threads = True
        _port = _server.server_address[1]
        threading.Thread(target=_server.serve_forever, daemon=True).start()
        return _port
