# ovstorage

`ovstorage` is an async Python binding for the ovstorage portable storage
library. It gives applications one API for object I/O across storage backends
registered through ovstorage plugins.

The package is pre-1.0. The API is usable, but compatibility guarantees are
still settling.

## Install

```sh
pip install ovstorage
```

The wheel includes the Python extension package, `py.typed`, package plus
per-layer type stubs for Python 3.10 and newer, and the first-party plugin
libraries: S3, GCS, Azure, Nucleus, HTTP, OpenDAL, broker, the Omniverse storage
service client, and the core and cache Layer families. `pip install ovstorage`
is enough to use any of them.

The libraries ship in the wheel, but nothing loads implicitly. Reach them with
`ovstorage.bundled_plugins_dir()` and hand that to a `PluginRegistry`:

```python
registry = ovstorage.PluginRegistry([ovstorage.bundled_plugins_dir()])
stack = await (
    ovstorage.Stack(root="s3")
    .with_registry(registry)
    .backend(ovstorage.plugin.PluginBackend("s3"))
    .build()
)
```

## Quick Start

```python
import asyncio
import tempfile
from pathlib import Path

import ovstorage


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        request = ovstorage.ConnectionRequest("file")
        request.add_config("root", ovstorage.ConfigValue.string(str(root)))
        storage = await (
            ovstorage.Stack(root="files")
            .backend(ovstorage.file.FileBackend("files"))
            .connection("files", request)
            .build()
        )

        address = (root / "hello.txt").as_uri()
        await storage.write(address, b"hello from ovstorage")

        data, info = await storage.read_bytes(address, max_bytes=1024)
        print(data.decode("utf-8"))
        print(info.size)


asyncio.run(main())
```

## Notes

- The Python API is async-first. Long-running layer methods return coroutines compatible with `asyncio.create_task`, `gather`, and `wait_for`. Note that `asyncio.wait` requires explicit tasks — wrap with `asyncio.create_task(stack.method(...))` first.
- `read_bytes(address)` returns `(bytes, Info)`.
- Use `read_bytes(..., max_bytes=...)` for bounded reads or `materialize` for
  a stable local path.
- Errors are exposed as `ovstorage.Error` subclasses such as
  `NotFoundError`, `NoRouteError`, and `PermissionDeniedError`.
- `file` is the one built-in Layer kind. Other standard Layers load factories
  from an explicit `PluginRegistry` during `Stack.build()`. Applications may
  also declare native Python Layers by subclassing `LayerBase`.
- A stack with Python layer bodies captures the asyncio loop it is built on and
  dispatches those bodies there. By default that is the loop `Stack.build()` was
  awaited on. Pass `Stack.build(loop=owned.loop)` with an `ovstorage.OwnedLoop`
  to run those bodies on a producer-owned loop instead, so the stack can be
  driven from threads that are not running an asyncio loop. That loop must stay
  alive for the life of the stack (and of any handle exported from it); once it
  stops, operations fail with a typed `NotConfiguredError` rather than hanging:

  ```python
  with ovstorage.OwnedLoop() as owned:
      stack = await ovstorage.Stack(root="leaf").backend(leaf).build(
          loop=owned.loop
      )
      data, info = await stack.read(address)
  ```

## More Information

- Python guide:
  <https://github.com/NVIDIA-Omniverse/ovstorage/tree/main/docs/public/library-python>
- Source:
  <https://github.com/NVIDIA-Omniverse/ovstorage>
