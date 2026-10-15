---
name: ovstorage-services/api-contribute/release
description: Cut an ovstorage calendar release (YY.MM), promote API maturity stages, publish conformance package
type: skill
---

# Skill: ovstorage-services/api-contribute/release

> **Status:** aspirational in places. The `YY.MM` calendar-version model below
> is a proposal, not current tooling. Agents cutting a spec release today should
> update the vendored Storage API contract snapshot through the project-approved
> source process.

Cut a release bundle. Promote API stages. Publish the conformance package. Update CHANGELOG.

## 1. What a release contains (current storage-api)

A SemVer tag on `storage-protos` (e.g. `1.0.0-beta.4`) is a coherent bundle of:

- Proto + OpenAPI specs for the `storage` surfaces (`capabilities`, `filefolder`, `fileobject`, `metadata`, `versioning`) at their declared maturity (`v1alpha`, `v1beta`)
- `conformance_tests/` package matching those specs (pytest-bdd features + step definitions + test data generators)
- Updated [`CHANGELOG.md`](../../apis/storage-api/CHANGELOG.md)
- Reference Python backend (`filesystem_example/`)
- `LICENSE.txt`, `CODEOWNERS`, `catalog-info.yaml`

Updating the vendored contract snapshot is outside ordinary library changes and
should be isolated in its own PR.

## 2. Release cadence (aspirational)

*TBD — cadence policy for the monorepo bundle layer (above the per-surface SemVer). Options: every 2 months? Aligned to Omniverse Kit release train? Aligned to Isaac Sim release? Not yet decided.*

## 3. Pre-release checklist

- [ ] All open `contribute/add-endpoint` PRs for the cycle are merged
- [ ] Conformance suite passes against the reference backend for every `(api, version)` pair that's in scope
- [ ] CHANGELOG updated (one subsection per API with added / changed / deprecated)
- [ ] `api-reference.md` reflects the final matrix
- [ ] Version-matrix tables in every `<api>-api/AGENTS.md` agree with the spec
- [ ] Maturity promotions recorded (see §4)

## 4. Maturity promotion (v1alpha → v1beta → v1)

*TBD — exact criteria. Expected:*

### Criteria to promote `v1alpha` → `v1beta`
- No breaking changes for one full release cycle
- ≥90% conformance coverage across declared scenarios
- At least one non-reference implementation has passed conformance
- Deprecation pass on overlapping `v1alpha` features

### Criteria to promote `v1beta` → `v1`
- Two full release cycles at `v1beta` with no breaking changes
- 100% conformance coverage, all scenarios PASS on reference
- ≥2 non-reference implementations passed conformance
- Formal sign-off from API owner

## 5. Tag the release

The spec source is outside this repository. Do not invent tags locally for
vendored contract content. Import released API bundles through the
project-approved source process, then update this repo's mirrored snapshot in an
isolated PR.

A monorepo-level `YY.MM` bundle tag is a proposal, not current tooling.

## 6. Publish artifacts

Future monorepo bundles would need their own publication decision.

## 7. Update service repo `api-support.yaml` references

Each service repo declares which `YY.MM` spec bundle it supports. After releasing `26.04`, service repos can bump their `api-support.yaml` to reference the new bundle.

*TBD — coordination process: PR to each service repo? Automated?*

## 8. Announce

*TBD — channels:*

- CHANGELOG notes
- Release announcement through the approved project channel
- Blog post for major maturity promotions (`v1beta` → `v1`)

## 9. Post-release

- [ ] Tag next-release milestone in issue tracker
- [ ] Deprecations that hit end-of-life this release are removed (see [`architecture.md`](architecture.md) §6)

## See also

- [`architecture.md`](architecture.md) — maturity policy
- [`add-endpoint.md`](add-endpoint.md) — what merged during the cycle
- [`../../apis/storage-api/CHANGELOG.md`](../../apis/storage-api/CHANGELOG.md) — vendored contract version history
- [`../../apis/storage-api/README.md`](../../apis/storage-api/README.md) — mirrored release snapshot overview
