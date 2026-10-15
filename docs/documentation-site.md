# Building the documentation site

The documentation site is built with Sphinx and the NVIDIA Sphinx theme. The
landing pages in this directory introduce the project and link into the
component guides under `ovstorage/docs/public/` and `ovstorage-usd-resolver/docs/`,
which are published from their own locations. For a browsable index without
building the site, see the [documentation index](README.md).

**Prerequisites:** [uv](https://docs.astral.sh/uv/). The docs toolchain requires
Python 3.11 or newer; `uv` downloads a suitable interpreter if needed.

Starting from the combined repository root:

```sh
cd docs
make html
```

Then, from the same `docs/` directory, serve the output locally:

```sh
uv run python -m http.server 8000 -d _build/html
```

Open <http://localhost:8000/> in a browser.

## How the site is assembled

- `conf.py` uses the repository root as the Sphinx source directory and
  `include_patterns` to select the pages, so component guides keep their paths
  and their relative Markdown links resolve to site pages.
- Links to files that are not pages, such as examples and tools, are rewritten
  to the file on GitHub by `_ext/github_links.py`.
- `DOCS_GITHUB_URL` and `DOCS_GITHUB_REF` set the repository and branch those
  links point at. They default to `https://github.com/NVIDIA-Omniverse/ovstorage`
  and `main`, so a fork or pull-request build links to upstream `main` unless
  you set both to the repository and branch you are building.
- The landing page is `docs/index.md`; the build writes a root `index.html`
  that redirects to it.
- Add a new component guide to a `toctree` in `index.md` so it appears in the
  navigation. `conf.py` builds only `docs/*.md`, `ovstorage/docs/public/**` and
  `ovstorage-usd-resolver/docs/**`; for a page anywhere else, also extend
  `include_patterns`, or the page is skipped and its toctree entry warns.
- `requirements.in` lists the toolchain; `requirements.txt` is its hash-locked
  resolution. After changing `requirements.in`, regenerate the lock with
  `uv pip compile requirements.in --universal --python-version 3.11 --generate-hashes -o requirements.txt`.

## Continuous integration

[`docs.yml`](../.github/workflows/docs.yml) builds the site for every pull
request. Its deploy job runs only in the upstream `NVIDIA-Omniverse/ovstorage`
repository, for pushes to `main` and manual runs from `main`, so forks and
mirrors build the site but never publish it. The workflow ships in the complete
public source archive; internal inspection branches omit it intentionally, so
this link resolves only in the public repository.

Before the first deployment, a maintainer of the upstream repository sets
**Settings → Pages → Build and deployment → Source** to **GitHub Actions**.
Until then the deploy job fails because Pages is not enabled.
