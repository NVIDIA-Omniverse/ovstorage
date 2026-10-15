**Object metadata now declares whether an etag is a strong or weak validator.**
Rust, C, C++, Python, REST, broker, and MCP callers can inspect the declaration
without parsing the opaque etag token. The byte cache uses only strong
validators as content keys, while weak or unspecified validators follow the
untrusted path. Because the built-in `file://` backend declares its synthesized
validator weak, a byte cache over a file root bypasses byte lookup and fill.
The broker's lost-backing fallback likewise cannot serve a `file://` root,
because that fallback requires a strong validator to publish an availability
row.
Nucleus etags and bare or malformed HTTP-derived etags retain their opaque
tokens but declare no strength, so they also take the untrusted byte-cache path.

Layer plugin ABI 16 identifies the preceding `Connection.owning_target` layout
change, and ABI 17 adds the `list_stream` slot. Etag strength therefore uses
ABI 18, an ABI break from ABI 17: the new fields grow structs that have no
`struct_size` prefix, and the loader requires an exact ABI match. Every
out-of-tree ABI-17 plugin is refused at load and must be rebuilt against the
ABI-18 headers before it can load. Redirect producers that select a custom
validator header receive that header value verbatim, including quotes or a
literal `W/` prefix; only the standard `ETag` header is normalized. Mid-stream
redirect resume uses any nonempty configured validator as its textual response
guard; the strength declaration does not gate resume.
