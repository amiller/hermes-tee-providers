"""Synthetic transport tests; bypass registration so no proxy starts on import."""
import importlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import http.server
import threading

import httpx

package = types.ModuleType("synthetic_tee_plugin")
package.__path__ = [str(Path(__file__).resolve().parents[1] / "tee-providers")]
sys.modules[package.__name__] = package
transport = importlib.import_module(package.__name__ + "._transport")
crypto = importlib.import_module(package.__name__ + "._crypto")
boundary = importlib.import_module(package.__name__ + "._tool_boundary")


class ToolBoundaryTests(unittest.TestCase):
    def make_client(self, reply=None, algo="ecdsa", variant=transport.E2EETransport):
        model_private, model_public = crypto._generate_keypair(algo)
        calls = []

        def upstream(request):
            payload = json.loads(request.content)
            calls.append(payload)
            content = crypto._decrypt_content(payload["messages"][0]["content"], model_private, algo)
            self.assertEqual(content, "synthetic prompt")
            self.assertNotIn(b"synthetic prompt", request.content)
            for field in ("reasoning", "reasoning_content"):
                if field in payload["messages"][0]:
                    self.assertEqual(crypto._decrypt_content(payload["messages"][0][field], model_private, algo), "synthetic reasoning")
                    self.assertNotIn(b"synthetic reasoning", request.content)
            client_public = request.headers[variant._HDR_CLIENT_PUB]
            if reply is not None:
                return httpx.Response(200, content=reply, headers={"content-type": "text/event-stream" if payload.get("stream") else "application/json"})
            answer = crypto._encrypt_content("synthetic answer", client_public, algo)
            data = {"choices": [{"message": {"content": answer}, "delta": {"content": answer}}]}
            if payload.get("stream"):
                return httpx.Response(200, content=("data:" + json.dumps(data) + "\n\ndata: [DONE]\n\n").encode(), headers={"content-type": "text/event-stream"})
            return httpx.Response(200, json=data)

        adapter = variant(model_public, algo, inner=httpx.MockTransport(upstream))
        return httpx.Client(transport=adapter), calls

    def body(self, **fields):
        return {"messages": [{"role": "user", "content": "synthetic prompt"}], **fields}

    def test_native_requests_refuse_before_upstream(self):
        canary = "synthetic-native-canary"
        cases = [
            self.body(tools=[{"type": "function", "function": {"description": canary}}]),
            self.body(functions=[{"name": canary}]), self.body(tool_choice={"function": {"name": canary}}),
            self.body(function_call={"name": canary}),
            {"messages": [{"role": "assistant", "tool_calls": [{"function": {"arguments": canary}}]}]},
            {"messages": [{"role": "assistant", "function_call": {"arguments": canary}}]},
            {"messages": [{"role": "tool", "content": canary}]},
            {"messages": [{"role": "function", "name": canary, "content": canary}]},
            {"messages": [{"role": "user", "content": [{"type": "text", "text": canary}]}]},
            {"messages": [{"role": "user", "content": "text", "audio": {"data": canary}}]},
            {"messages": [{"role": "assistant", "reasoning": {"text": canary}}]},
        ]
        client, calls = self.make_client()
        with client:
            for body in cases:
                with self.subTest(body=body), self.assertRaises(boundary.UnsupportedEncryptedChat) as error:
                    client.post("https://synthetic.invalid/v1/chat/completions", json=body)
                self.assertNotIn(canary, str(error.exception))
        self.assertEqual(calls, [])

    def test_text_encryption_remains_available_for_both_algorithms(self):
        for algo in ("ecdsa", "ed25519"):
            for streaming in (False, True):
                with self.subTest(algo=algo, streaming=streaming):
                    client, calls = self.make_client(algo=algo)
                    with client:
                        body = self.body(stream=streaming, tools=[], functions=[], tool_choice="none", function_call="none")
                        body["messages"][0].update(reasoning="synthetic reasoning", reasoning_content="synthetic reasoning")
                        response = client.post("https://synthetic.invalid/v1/chat/completions", json=body)
                    self.assertIn("synthetic answer", response.text)
                    self.assertNotIn("tools", calls[0])
                    self.assertNotIn("functions", calls[0])

    def test_venice_variant_also_refuses_native_tools(self):
        client, calls = self.make_client(variant=transport.VeniceE2EETransport)
        with client, self.assertRaises(boundary.UnsupportedEncryptedChat):
            client.post("https://synthetic.invalid/v1/chat/completions", json=self.body(tools=[{"name": "synthetic"}]))
        self.assertEqual(calls, [])

    def test_native_json_response_is_refused(self):
        for message in ({"tool_calls": [{"function": {"arguments": "synthetic"}}]}, {"function_call": {"arguments": "synthetic"}}):
            client, _ = self.make_client(json.dumps({"choices": [{"message": message}]}).encode())
            with client, self.assertRaises(boundary.UnsupportedEncryptedChat):
                client.post("https://synthetic.invalid/v1/chat/completions", json=self.body())

    def test_stream_spacing_fragments_and_unterminated_tail_cannot_bypass_guard(self):
        for prefix in ("data:", "data: ", "data:  "):
            for suffix in ("", "\n", "\r\n"):
                for delta in ({"tool_calls": [{"function": {"arguments": "synthetic"}}]}, {"function_call": {"arguments": "synthetic"}}, {"nearai_tool_result": {"output": "synthetic"}}):
                    value = (prefix + json.dumps({"choices": [{"delta": delta}]}) + suffix).encode()
                    private, public = crypto._generate_keypair("ecdsa")
                    adapter = transport.E2EETransport(public, "ecdsa")
                    with self.subTest(prefix=prefix, suffix=suffix), self.assertRaises(boundary.UnsupportedEncryptedChat):
                        list(adapter._decrypt_sse((value[i:i+3] for i in range(0, len(value), 3)), private))
                    adapter.close()

    def test_stream_refusal_closes_upstream(self):
        closed = []

        class Stream(httpx.SyncByteStream):
            def __iter__(self):
                yield b'data:{"choices":[{"delta":{"tool_calls":[]}}]}\n\n'

            def close(self):
                closed.append(True)

        private, public = crypto._generate_keypair("ecdsa")
        adapter = transport.E2EETransport(public, "ecdsa", inner=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Stream(), headers={"content-type": "text/event-stream"})))
        with httpx.Client(transport=adapter) as client, self.assertRaises(boundary.UnsupportedEncryptedChat):
            client.post("https://synthetic.invalid/v1/chat/completions", json=self.body(stream=True))
        self.assertTrue(closed)

    def test_loopback_proxy_returns_static_refusal_without_plaintext_retry(self):
        proxy = importlib.import_module(package.__name__ + "._proxy")
        upstream_client, calls = self.make_client()
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), proxy._Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict(proxy._ROUTES, {"synthetic": {"root": "https://synthetic.invalid"}}, clear=True), \
                 patch.object(proxy, "_e2ee_transport_for", return_value=upstream_client._transport), \
                 httpx.Client(trust_env=False) as client:
                url = f"http://127.0.0.1:{server.server_address[1]}/synthetic/v1/chat/completions"
                bad = self.body(tools=[{"function": {"description": "synthetic-sensitive-canary"}}])
                response = client.post(url, json=bad)
                self.assertEqual(response.status_code, 502)
                self.assertIn("text only", response.text)
                self.assertNotIn("synthetic-sensitive-canary", response.text)
                self.assertEqual(calls, [])
                good = client.post(url, json=self.body())
                self.assertEqual(good.status_code, 200)
                self.assertIn("synthetic answer", good.text)
                self.assertEqual(len(calls), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            upstream_client.close()
            proxy._PLAIN.close()

    def test_bad_stream_json_is_refused(self):
        private, public = crypto._generate_keypair("ecdsa")
        adapter = transport.E2EETransport(public, "ecdsa")
        with self.assertRaises(boundary.UnsupportedEncryptedChat):
            list(adapter._decrypt_sse([b'data:{"choices": malformed}'], private))
        adapter.close()


if __name__ == "__main__":
    unittest.main()
