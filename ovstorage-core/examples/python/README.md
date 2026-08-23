# Python examples

The numbered examples build one idea at a time. They use only the Python
standard library and the `ovstorage` wheel.

## Prerequisites

From a repository checkout:

```sh
make dist-wheel
export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/dist/plugins"
pip install dist/wheels/ovstorage-*.whl
cd ovstorage-core/examples/python
```

In an unpacked release archive, the plugins are already present under
`plugins/`, but the wheel is not: it is published as its own release asset
beside the archive rather than inside it. Install it from PyPI at the archive's
version, running from this directory (`examples/python/`), which is what the
relative path below assumes:

```sh
pip install "ovstorage==$(cat ../../VERSION)"
python 01_file.py
```

The wheel bundles the first-party plugins these examples use, so that is
enough on its own — `OVSTORAGE_PLUGIN_DIR` is optional, and the examples fall
back to `ovstorage.bundled_plugins_dir()` when it is unset. Set it to run
against a different set of libraries instead, such as the archive's:

```sh
export OVSTORAGE_PLUGIN_DIR="$(cd ../.. && pwd)/plugins"
```

The archive's `plugins/` carries one library the wheel does not: the
`test_only` conformance fixture, which hosts refuse unless a caller opts in.

`file` is the only Layer kind built into the Python host. Every other kind in
these examples is resolved from a plugin in `OVSTORAGE_PLUGIN_DIR`. This is
intentional: the same plugin libraries can be loaded by the Rust, Python, and
C/C++ hosts.

## Tutorial

Run the examples in order:

1. [`01_file.py`](01_file.py) builds the smallest useful Stack, writes one
   local object, and reads it back. It needs no plugin.
2. [`02_object_operations.py`](02_object_operations.py) adds `stat`, `list`,
   bounded reads, and deletion while keeping the same one-backend Stack.
3. [`03_load_a_plugin.py`](03_load_a_plugin.py) explicitly loads the core
   plugin and puts its `router` over the built-in file backend.
4. [`04_file_and_http.py`](04_file_and_http.py) routes both `file://` and
   HTTP(S) addresses. It demonstrates a capability difference directly:
   files can be listed, while the HTTP backend returns `Unsupported`.
5. [`05_cache.py`](05_cache.py) loads the cache plugin and composes both
   `metadata_cache` and `byte_cache` above the file/HTTP router. It supplies
   the cache directories through Layer configuration.
6. [`06_native_layers.py`](06_native_layers.py) adds native Python Layers to
   the same Stack: a GitHub repository backend and a wrapper that logs reads
   and lists. The GitHub backend browses the public
   `NVIDIA-Omniverse/ovstorage` repository through the GitHub Contents API.

For example:

```sh
python 01_file.py
python 02_object_operations.py
python 03_load_a_plugin.py
python 04_file_and_http.py
python 05_cache.py
python 06_native_layers.py
```

Examples 4 and 5 accept an optional anonymous HTTP(S) object URL. Example 6
uses the public GitHub API and may be subject to GitHub's anonymous rate
limits. Logging Layers must redact userinfo, query strings, and fragments
because storage addresses can contain presigned credentials; example 6
demonstrates that rule.

## Additional examples

- [`hello_storage.py`](hello_storage.py) is a longer local-file walkthrough.
- [`local_file_browser.py`](local_file_browser.py) and
  [`local_file_browser_web.py`](local_file_browser_web.py) build a small local
  content browser.
- [`https_preview.py`](https_preview.py) previews one anonymous HTTPS object.
- [`services_config_probe.py`](services_config_probe.py) and
  [`services_client_smoke.py`](services_client_smoke.py) exercise an
  Omniverse Storage Service connection supplied by the user. The probe loads
  the plugin file kind `services_client`; its configuration uses backend kind
  `omniverse-storage-service` and top-level connection entries:

  ```toml
  [[connections]]
  backend_kind = "omniverse-storage-service"
  display_name = "example-service"

  [connections.config]
  address = "https://storage.example.com"
  ```
