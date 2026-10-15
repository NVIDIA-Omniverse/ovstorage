Up: [ovstorage-expert](../SKILL.md)

# Related experts

ovstorage is the content-access part of Omniverse Content Services. The other parts each have their own repository and expert skill, and a question often arrives here that is partly theirs. Answer the ovstorage and resolver part from this skill, then hand the rest to the expert that owns it.

## How to hand off

1. **Find the boundary.** Say which part of the question is about ovstorage or the resolver and which part belongs to another product.
2. **Answer your part** from this skill's references.
3. **Name the expert and the question.** Give the product, the skill to load, and a specific question to ask it, for example: "Ask the usd-content-workspace expert: which Discovery URL does this deployment's Storage Service advertise?"
4. **Check access.** ovstorage and ovpackage are public. usd-content-workspace, ovlive, and usd-caches repositories are not publicly available; refer only callers with access to the repository and its expert. Give everyone else the published documentation linked below, or say the answer needs that product.
5. **Use the checkout only if you opened it.** If you can read the other repository's checkout, read its `AGENTS.md` and load the named skill before answering for it. Give a local path to another checkout, including the skill locations below, only after you have opened it; otherwise name the skill alone.
6. **Don't answer for another product from memory.** The summaries below are for routing only. Facts about another product's behavior, configuration, or APIs come from its own expert or source.

If you can't tell which product a caller needs, ask: "Are you reading content into an application, running the services that hold it, editing live with other people, packaging versions to distribute, or making repeat reads faster?"

| The caller wants to | Expert |
| --- | --- |
| Read, write, list, or materialize content from an application, CLI, MCP, or USD host | This skill |
| Deploy, call, secure, or extend the Content Services APIs and services, or connect Kit to them | `usd-content-workspace-expert` |
| Edit a USD stage live with other participants | `ovlive-expert` |
| Version, publish, install, or mirror sets of assets | `ovpackage-cli` or `ovpackage-api` |
| Make repeat reads faster on a workstation or across a cluster | `usd-caches-expert` |

## usd-content-workspace

- **Expert:** `usd-content-workspace-expert`.
- **Skill location, once you have opened the checkout:** `skills/usd-content-workspace-expert/`.
- **Owns:** the Content Services APIs and their reference services: Storage, Metadata, Discovery, Notifications, Permissions, User Info, and Thumbnails, and it deploys ovlive's Live Edit service beside them. It covers building, deploying (prebuilt NGC containers and Helm charts, Kubernetes, or local processes), securing, and operating them; calling their versioned gRPC and REST APIs; custom service-side adapters; conformance tests; and connecting Kit, the Client Library, or Navigator. Its services are reference implementations meant to be replaced or extended behind the same contracts.
- **Where it meets ovstorage:** ovstorage is a client of the Storage Service through the `omniverse-storage-service` backend ([plugin-services-client.md](../../../ovstorage/docs/public/plugin-storage/plugin-services-client.md)), which discovers the endpoint over HTTP and redirects reads ([configure.md](storage/configure.md#redirects)). Stay here for that backend's configuration and sign-in; send everything about the service itself there.
- **Naming:** in that expert, "ovstorage" means only this client library, never the services or a deployment. The services' earlier product name, "Omniverse Storage APIs", is retired.
- **Hand off when:** the caller is building or adapting a storage service, implementing a Storage API, running conformance, deploying or operating any Content Services service, or asking how Kit or Navigator reaches those services. A storage *plugin* for ovstorage stays in this checkout: the [plugin contract](../../../ovstorage/docs/public/plugin-development/README.md) and the [`ovstorage-contributor-author-storage-plugin`](../../../ovstorage/skills/ovstorage-contributor-author-storage-plugin/SKILL.md) skill.
- **Questions to ask it:** "Which Discovery URL and auth configuration does this deployment expose for the Storage Service?" "Which Storage API version does this deployment serve?"
- **Published docs:** the [Content Services storage guide](https://docs.omniverse.nvidia.com/ovstorage/ovstorage-guide/latest/index.html).

## ovlive

- **Expert:** `ovlive-expert`.
- **Skill location, once you have opened the checkout:** `skills/ovlive-expert/`.
- **Owns:** live OpenUSD collaboration: the `omni_usd_live` client runtime with its C ABI, C++ adapter, `omni.usd.live` Python package, and `omni.kit.live_services` Kit extension; the `.live` layer format and `live://` URIs; and the Live Edit service, a gRPC service authorized through a Storage Service.
- **Where it meets ovstorage:** ovstorage supplies the base scenes and assets a host composes under live layers; live-layer traffic uses ovlive's own protocol and its own `ArResolver` for the `live` scheme. This resolver claims `s3;http;https;hf` by default, excluding `live`. Custom builds can advertise other schemes, including `live`, so hosts must check the actual advertised schemes for overlap before loading both resolvers. Nothing in this checkout tests them together in one process, so don't claim that it works; ask the ovlive expert.
- **Hand off when:** the caller wants live sessions, presence, `.live` layers, Live Edit deployment, or diagnosis of live edits. Nucleus live layers served through `omni.client` belong to neither product.
- **Questions to ask it:** "Can `omni.usd.live` run in a host that also loads the ovstorage resolver for `s3` base layers?" "Which Storage Service must the Live Edit service authorize against?"
- **Published docs:** none. Tell callers without access that the answer needs ovlive.

## ovpackage

- **Repository:** [NVIDIA-Omniverse/ovpackage](https://github.com/NVIDIA-Omniverse/ovpackage) (public).
- **Expert:** `ovpackage-cli` for the CLI and `ovpackage-api` for the async Python API.
- **Skill location, once you have opened the checkout:** `.agents/skills/`.
- **Owns:** versioned asset packages. It creates, publishes, installs, updates, mirrors, exports, imports, freezes, catalogs, diffs, and checks them across local storage, S3, Azure, GCS, Nucleus, and a Storage API service, and keeps the `.wrapp` metadata format for existing workflows. It preserves directory layout and does not rewrite USD references.
- **Where it meets ovstorage:** they are complementary, not layered. ovstorage reads and writes individual objects for an application; ovpackage gives a set of files a name, a version, and dependencies, and moves it as a unit. ovpackage uses its own storage adapters and does not depend on the ovstorage Python package, so ovstorage configuration does not carry over to it.
- **Hand off when:** the caller wants reproducible content versions, publishing, installing a known version into a workspace, mirroring a package to another bucket or region, or offline transfer.
- **Questions to ask it:** "How do I publish this directory as a versioned package to S3 and install that version in CI?" "Can a package be mirrored to a bucket in another region and kept current?"

## usd-caches

- **Expert:** `usd-caches-expert`.
- **Skill location, once you have opened the checkout:** `skills/usd-caches-expert/`.
- **Owns:** three caches: the **local cache** (`local-cache`, Hub Workstation Cache) for one workstation or node, the **shared content cache** (`shared-content-cache`, OVCC), an HTTP caching reverse proxy deployed on Kubernetes near many readers, and the **shared derived-data cache** (OVDC) for RTX derived data. It covers installers, NGC artifacts, sizing, deployment, configuration, and validation.
- **Where it meets ovstorage:** ovstorage and the resolver hold no shared byte cache. The resolver caches no bytes, and ovstorage's `byte_cache` and `metadata_cache` Layers serve one host. ovstorage's experimental `hub_cache` wrapper Layer caches object bytes in a local Hub; its keys and behavior may change, and Hub accepts unauthenticated local writes, so enable it only where every local process is trusted ([configuration.md](../../../ovstorage/docs/public/configuration.md), Layer kinds table). This checkout defines no OVCC integration, so don't infer ovstorage settings for it.
- **Recommend:** the local cache first for single-machine read latency; the shared content cache only when several nodes repeat the same reads.
- **Hand off when:** the caller asks how to install, run, size, or validate Hub, OVCC, or OVDC, or how clients reach a shared cache. Stay here for the ovstorage side of `hub_cache`.
- **Questions to ask it:** "Which `hub_cache` key scheme should this host use, and how do I confirm Hub is serving hits?" "Can OVCC cache reads that ovstorage's `s3` backend redirects to presigned URLs?"
- **Published docs:** [local cache](https://docs.omniverse.nvidia.com/utilities/latest/cache/hub-workstation.html), [shared content cache](https://docs.omniverse.nvidia.com/ovcaches/ovcontentcache/latest/index.html), [shared derived-data cache](https://docs.omniverse.nvidia.com/ovcaches/ovderivedcache/latest/index.html).
