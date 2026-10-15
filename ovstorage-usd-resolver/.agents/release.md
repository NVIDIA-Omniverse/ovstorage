# Verify source consumption and local installation

No resolver wheels are published to PyPI or elsewhere for this release.
The ovstorage library has its own published packages. This guide applies to the
public resolver component; release promotion is a maintainer operation outside
this checkout.

Read [building from source](../docs/building.md), the
[compatibility matrix](../docs/compatibility-matrix.md) and
[API stability policy](../docs/api-stability.md). Run commands from the resolver
component root, the directory containing its README and CMakeLists.txt.

- Build and run CTest first without SDKs, then with the exact supported host SDK
  and matching ovstorage sources/providers. A no-SDK pass does not qualify a
  plugin, provider or host integration.
- Check plugin discovery and deterministic remote composition. Retain the
  source revisions, SDK receipt, compiler/runtime identity and test results.
- Run applicable live-provider checks separately; a loopback fixture does not
  qualify an external service or its write behavior.
- For local native installation, follow [native-package.md](../docs/native-package.md)
  and run its installed-consumer recipe against the installed prefix.
- The [optional Python package](../docs/python-wheels.md) has its own pinned SDK
  and installed-consumer checks. Building it locally does not imply publication.
- Review [CHANGELOG.md](../CHANGELOG.md), supported interfaces, licensing and
  public documentation for the selected source revision.
- For a tagged revision, confirm `VERSION`, the tag and the dated
  `CHANGELOG.md` section agree.
- Confirm the source archive contains the public headers, implementation,
  plugin metadata, tests, docs, `LICENSE`, `NOTICE` and
  `THIRD_PARTY_NOTICES.md`.
- Reject private endpoints, credentials, machine-local paths and non-public
  operational material in the source and in any local evidence you share.

Do not infer publication approval from passing tests, a local install, or an
internal CI artifact. Native archive/Conan delivery requires its own explicit
release decision.
