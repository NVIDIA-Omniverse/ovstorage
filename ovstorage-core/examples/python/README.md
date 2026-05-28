# Python Examples

These examples demonstrate the `ovstorage` Python binding with only the
Python standard library and the local `ovstorage` wheel.

Start with `hello_storage.py` when you are learning the API. Read the file
browser scripts after that if you want examples of listing and previewing a
small content tree.

## Prerequisites

Build the Python binding and plugins from the repo root:

```sh
make dist-wheel
export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/dist/plugins"
pip install dist/wheels/ovstorage-*.whl
```

## Hello Storage

`hello_storage.py` is the smallest complete local example. It creates a
temporary `file://` route, writes an object, stats it, lists it, reads it,
materializes it, and deletes it.

```sh
python ovstorage-core/examples/python/hello_storage.py
```

## File Browser

`local_file_browser.py` creates a small temporary content tree, lists it through
`ovstorage`, and previews text-like objects.

```sh
python ovstorage-core/examples/python/local_file_browser.py
```

`local_file_browser_web.py` is a local app demo backed by the same `file://`
route. The UI is local HTTP, but listing and preview requests go through the
ovstorage Python binding.

```sh
python ovstorage-core/examples/python/local_file_browser_web.py --open
```

## HTTPS Preview

`https_preview.py` reads one anonymous HTTPS object URL. The HTTP plugin does
not list remote directories, so this example is intentionally scoped to an
exact object URL.

```sh
python ovstorage-core/examples/python/https_preview.py https://www.example.com/
```

Replace the URL with any anonymous HTTPS object URL you want to inspect.

## Service Config Probe

`services_config_probe.py` loads the services-client plugin and a user-supplied
`ovstorage.toml`, prints configured address roots, and can optionally run a
`stat`, `list`, or `read` probe against one address.

The sample loads the plugin file kind `services_client`. In the config file,
the corresponding backend kind is `omniverse-storage-service`. A minimal
service connection config has this shape:

```toml
[[connections]]
backend_kind = "omniverse-storage-service"
display_name = "example-service"

[connections.config]
discovery_url = "https://storage.example.com"
```

Use the service URL and authentication settings for the deployment you are
testing. Keep credentials and environment-specific URLs outside the repo.

```sh
python ovstorage-core/examples/python/services_config_probe.py \
  --config path/to/ovstorage.toml

python ovstorage-core/examples/python/services_config_probe.py \
  --config path/to/ovstorage.toml \
  --address <storage-address> \
  --operation stat
```
