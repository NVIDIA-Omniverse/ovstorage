# C++20 examples

These examples use the header-only `ovstorage.hpp` wrapper and the hand-written
C host shipped in this source tree. They mirror the numbered Python tutorial
and build one concept at a time:

1. [`01_file.cpp`](01_file.cpp) uses the one built-in kind, `file`.
2. [`02_object_operations.cpp`](02_object_operations.cpp) adds common object
   operations and typed result handling.
3. [`03_load_a_plugin.cpp`](03_load_a_plugin.cpp) loads the core plugin and
   resolves its `router` kind.
4. [`04_file_and_http.cpp`](04_file_and_http.cpp) routes both file and HTTP
   addresses and shows that HTTP does not support directory listing.
5. [`05_cache.cpp`](05_cache.cpp) loads both metadata and content cache Layers
   from the cache plugin and supplies their Layer configuration.
6. [`06_native_layer.cpp`](06_native_layer.cpp) creates an in-process C++
   logging wrapper from the standard pass-through vtable. The built root is
   exported into the native wrapper and imported back as one driveable Stack
   root.

Build all examples with the source distribution:

```sh
make -f Makefile.example examples
```

The first two need no plugins. Examples 3–5 take the plugin directory as their
first argument. Examples 4 and 5 optionally take an anonymous HTTP(S) object
URL as their second argument.

```sh
build/tutorial_01_file
build/tutorial_02_object_operations
build/tutorial_03_load_a_plugin ../plugins
build/tutorial_04_file_and_http ../plugins
build/tutorial_05_cache ../plugins
build/tutorial_06_native_layer
```

The examples keep every loaded `ovstorage::Plugin` alive beside the
`ovstorage::Registry` and built root. A production application should use the
same lifetime rule.
