# ovstorage-plugin-huggingface

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-huggingface.md`](../../docs/public/plugin-storage/plugin-huggingface.md).

Read-only Hugging Face Hub backend (`huggingface`). One connection serves one
Hub repository (model, dataset, or space) under
`hf://{models|datasets|spaces}/<namespace>/<name>/`, speaking the Hub REST API
over `reqwest`. Supported operations: `stat`, `read` (streamed, ranged, and
LFS-redirected via signed CDN URLs), `list` and `list_stream` (one-level and
recursive), `list_versions`, and `get_latest_version`; version pins ride as a
`?revision=<ref>` address query. Under an `alias` layer the connection also
answers the Hub's own repository URL
(`https://huggingface.co/<namespace>/<name>/…` with its `http://`, `www.` and
`hf.co` twins, and the `datasets/` / `spaces/` forms) as generated spellings of
that root. All mutating operations keep the `Layer` trait defaults and answer
`Unsupported`.
