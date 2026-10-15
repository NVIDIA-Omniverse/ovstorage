# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise an installed wheel against a separately built, USD-only test host."""
import argparse
import concurrent.futures
import ctypes
import functools
import http.server
import json
import os
import sys
from pathlib import Path
import subprocess
import tempfile
import threading

import ovstorage_usd_resolver as resolver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--usd-sdk", type=Path, required=True)
    parser.add_argument("--provider-dir", type=Path, required=True)
    args = parser.parse_args()
    # The nopy SDK intentionally has no pxr Python module. This test host opens
    # USD stages in the same process, through the normal C++ USD API.
    uri = b"http://wheel.example/root.usda"
    with tempfile.TemporaryDirectory(prefix="resolver wheel ") as temporary:
        root = Path(temporary)
        (root / "root.usda").write_text('#usda 1.0\n(subLayers = [@child.usda@])\ndef Xform "Root" {}\n')
        (root / "child.usda").write_text('#usda 1.0\ndef Xform "Child" {}\n')
        # Reject a different host ABI before asking its loader to execute code.
        wrong_sdk = root / "wrong-sdk" / "lib"
        wrong_sdk.mkdir(parents=True)
        (wrong_sdk / ("ov_25.11usd_ms.dll" if os.name == "nt" else "libov_25.11usd_ms.so")).write_bytes(b"different SDK")
        mismatch = subprocess.run([sys.executable, "-c",
            "import sys; import ovstorage_usd_resolver as r; r.register_plugin(usd_sdk_root=sys.argv[1])",
            str(wrong_sdk.parent)], text=True, capture_output=True)
        assert mismatch.returncode != 0 and "does not match this wheel" in mismatch.stderr, mismatch.stderr
        mismatch = subprocess.run([sys.executable, "-c",
            "import sys; import ovstorage_usd_resolver as r; r.Runtime('missing.toml', usd_sdk_root=sys.argv[1])",
            str(wrong_sdk.parent)], text=True, capture_output=True)
        assert mismatch.returncode != 0 and "does not match this wheel" in mismatch.stderr, mismatch.stderr
        requests = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                requests.append(self.path)
                super().do_GET()

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(root)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = root / "ovstorage.toml"
        config.write_text('[ovstorage]\nroot = "http"\n[ovstorage.layers.http]\n'
            '[[ovstorage.connections]]\nbackend_kind = "http"\nconfig = { root_url = '
            + json.dumps(f"http://127.0.0.1:{server.server_port}/")
            + ', prefix = "http://wheel.example/" }\n')
        alternate_root = root / "alternate"
        alternate_root.mkdir()
        (alternate_root / "root.usda").write_bytes((root / "root.usda").read_bytes())
        (alternate_root / "child.usda").write_text('#usda 1.0\ndef Xform "Other" {}\ndef Xform "Extra" {}\n')
        alternate_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
            functools.partial(Handler, directory=str(alternate_root)))
        alternate_thread = threading.Thread(target=alternate_server.serve_forever, daemon=True)
        alternate_thread.start()
        alternate_config = root / "alternate.toml"
        alternate_config.write_text(config.read_text().replace(
            f":{server.server_port}/", f":{alternate_server.server_port}/"))
        try:
            # The constructor must validate/register before the independent host
            # is loaded, with no prior register_plugin() call from the caller.
            runtime = resolver.Runtime(config, plugin_directory=args.provider_dir, usd_sdk_root=args.usd_sdk)
            resolver.register_plugin(usd_sdk_root=args.usd_sdk)  # same SDK is idempotent
            probe = ctypes.CDLL(str(args.probe.resolve()))
            probe.ovs_test_open_stage.argtypes = [ctypes.c_char_p]
            probe.ovs_test_open_stage.restype = ctypes.c_int
            try:
                resolver.register_plugin(usd_sdk_root=wrong_sdk.parent)
                raise AssertionError("a different SDK was accepted after registration")
            except RuntimeError as error:
                assert "restart the process" in str(error), str(error)
            try:
                resolver.Runtime(root / "missing.toml")
                raise AssertionError("missing configuration was accepted")
            except RuntimeError:
                pass
            with runtime.bind():
                assert probe.ovs_test_open_stage(uri) == 2, "bound remote composition failed"
            with resolver.Runtime(alternate_config, plugin_directory=args.provider_dir, usd_sdk_root=args.usd_sdk) as alternate:
                with runtime.bind():
                    with alternate.bind():
                        assert probe.ovs_test_open_stage(uri) == 3, "nested runtime did not isolate routing"
                    assert probe.ovs_test_open_stage(uri) == 2, "outer runtime was not restored"
            assert any("child.usda" in path for path in requests), "composition did not fetch its dependency"
            assert probe.ovs_test_open_stage(uri + b"?unbound") == -1, "unbound host reused the Python runtime"

            barrier = threading.Barrier(2)

            def worker():
                with runtime.bind():
                    barrier.wait(timeout=15)
                    return probe.ovs_test_open_stage(uri)

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                assert list(pool.map(lambda _: worker(), range(2))) == [2, 2]
                outer = runtime.bind()
                outer.__enter__()
                def wrong_thread_exit():
                    try:
                        outer.__exit__(None, None, None)
                        return False
                    except RuntimeError:
                        return True
                assert pool.submit(wrong_thread_exit).result(), "cross-thread unbind was accepted"
                inner = runtime.bind()
                inner.__enter__()
                try:
                    outer.__exit__(None, None, None)
                    raise AssertionError("out-of-order exit was accepted")
                except RuntimeError:
                    pass
                inner.__exit__(None, None, None)
                outer.__exit__(None, None, None)

            with runtime.bind():
                runtime.close()
                assert probe.ovs_test_open_stage(uri) == 2, "closing the owner invalidated its binding"
            try:
                with runtime.bind():
                    raise AssertionError("closed runtime could bind")
            except RuntimeError:
                pass
            completed = subprocess.run([str(resolver.cli_path()), "doctor", "--json"],
                text=True, capture_output=True)
            assert completed.returncode == 0, completed.stdout + completed.stderr
            report = json.loads(completed.stdout)
            checks = {item["name"]: item for item in report["checks"]}
            assert checks["openusd_plugin_discovery"]["status"] == "ok", report
            assert "OvStorageUsdResolver" in checks["openusd_plugin_discovery"]["detail"], report
        finally:
            alternate_server.shutdown()
            alternate_server.server_close()
            alternate_thread.join()
            server.shutdown()
            server.server_close()
            thread.join()
    print("installed wheel: remote composition, thread scopes, lifetime, errors, CLI passed")


if __name__ == "__main__":
    main()
