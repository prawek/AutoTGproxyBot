"""Isolated TDLib testProxy worker. Only fixed JSON operations, never executable jobs."""
from __future__ import annotations

import ctypes
import importlib.metadata
import json
import os
import sys
import time

from app.proxy.decoder import canonical_secret
from app.proxy.network import validate_public_ip


class TdJson:
    def __init__(self):
        path = os.getenv("TDJSON_LIBRARY", "").strip()
        self.client = None
        if path:
            lib = ctypes.CDLL(path)
            lib.td_json_client_create.restype = ctypes.c_void_p
            lib.td_json_client_send.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            lib.td_json_client_receive.argtypes = [ctypes.c_void_p, ctypes.c_double]
            lib.td_json_client_receive.restype = ctypes.c_char_p
            lib.td_json_client_execute.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            lib.td_json_client_execute.restype = ctypes.c_char_p
            lib.td_json_client_destroy.argtypes = [ctypes.c_void_p]
            self.client = lib.td_json_client_create()
            self.send_raw = lambda data: lib.td_json_client_send(self.client, data)
            self.receive_raw = lambda delay: lib.td_json_client_receive(self.client, delay)
            self.execute_raw = lambda data: lib.td_json_client_execute(self.client, data)
            self.destroy = lambda: lib.td_json_client_destroy(self.client)
        else:
            import tdjson
            client_id = tdjson.td_create_client_id()
            self.send_raw = lambda data: tdjson.td_send(client_id, data)
            self.receive_raw = tdjson.td_receive
            self.execute_raw = tdjson.td_execute
            self.destroy = lambda: None
        self.execute_raw(json.dumps({"@type": "setLogVerbosityLevel", "new_verbosity_level": 0}).encode())
        self.version = "unknown"
        self.send({"@type": "getOption", "name": "version", "@extra": "worker-version"})
        until = time.monotonic() + 2
        while time.monotonic() < until:
            result = self.receive(.1)
            if result and result.get("@extra") == "worker-version":
                self.version = str(result.get("value", "unknown"))[:80]
                break

    def send(self, value):
        self.send_raw(json.dumps(value, ensure_ascii=True).encode())

    def receive(self, delay):
        raw = self.receive_raw(delay)
        return json.loads(raw) if raw else None


def emit(value):
    print(json.dumps(value, ensure_ascii=True, separators=(",", ":")), flush=True)


def main():
    try:
        engine = TdJson()
    except Exception:
        emit({"ready": False, "outcome": "unsupported_checker", "error_code": "native_engine_unavailable"})
        return
    try:
        package_version = importlib.metadata.version("tdjson")
    except importlib.metadata.PackageNotFoundError:
        package_version = "custom"
    metadata = {"engine_version": engine.version, "package_version": package_version,
                "client_profile_id": "tdlib-" + engine.version + "-" + sys.platform}
    emit({"ready": True, **metadata})
    if "--self-test" in sys.argv:
        engine.destroy()
        return
    try:
        while True:
            line = sys.stdin.buffer.readline(8193)
            if not line:
                break
            if len(line) > 8192:
                break
            try:
                job = json.loads(line)
                request_id = str(job["request_id"])[:64]
                ip = validate_public_ip(job["resolved_ip"])
                port = job["port"]
                dc_id = job.get("dc_id", 2)
                timeout = float(job.get("timeout", 12))
                if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise ValueError
                if isinstance(dc_id, bool) or dc_id not in (1, 2, 3, 4, 5) or not 1 <= timeout <= 30:
                    raise ValueError
                secret = canonical_secret(job["secret"])
                engine.send({"@type": "testProxy", "proxy": {
                    "@type": "proxy", "server": ip, "port": port,
                    "type": {"@type": "proxyTypeMtproto", "secret": secret}},
                    "dc_id": dc_id, "timeout": timeout, "@extra": request_id})
                until = time.monotonic() + timeout + .5
                result = None
                while time.monotonic() < until:
                    response = engine.receive(min(.2, max(.01, until - time.monotonic())))
                    if response and response.get("@extra") == request_id:
                        result = response
                        break
                if result and result.get("@type") == "ok":
                    emit({"request_id": request_id, "outcome": "success", **metadata})
                elif result and result.get("@type") == "error":
                    message = str(result.get("message", "")).lower()
                    # API/version/init errors are a checker failure, not evidence against a proxy.
                    if any(s in message for s in ("can't parse", "cannot parse", "unknown class", "initializ", "parameter", "not supported")):
                        outcome = "engine_error"
                    else:
                        outcome = "connect_timeout" if "timeout" in message or "time expired" in message else "auth_key_failed"
                    emit({"request_id": request_id, "outcome": outcome,
                          "error_code": "tdlib_" + str(result.get("code", 0)), **metadata})
                else:
                    emit({"request_id": request_id, "outcome": "connect_timeout", "error_code": "request_deadline", **metadata})
                    # Outstanding requests must not accumulate after a TDLib timeout malfunction.
                    break
            except Exception:
                emit({"outcome": "engine_error", "error_code": "invalid_worker_request"})
    finally:
        engine.destroy()


if __name__ == "__main__":
    main()
