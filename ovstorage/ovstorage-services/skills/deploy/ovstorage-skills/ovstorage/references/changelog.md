<div id="main-content" class="bd-main" role="main">

<div class="bd-content">

<div class="bd-article-container">

<div class="bd-header-article d-print-none">

<div class="header-article-items header-article__inner">

<div class="header-article-items__start">

<div class="header-article-item">

  - **
  - <span class="ellipsis">Changelog</span>

</div>

</div>

</div>

</div>

<div id="searchbox">

</div>

<div id="changelog" class="section">

<span id="id1"></span>

# Changelog

## v1.0.0 GA Release (April 2026)

Updated chart versions from EA2/beta to 1.0.0 GA:

| Service | EA2 Chart | v1.0.0 Chart |
|---------|-----------|--------------|
| `storage-service` | 0.7.19 | **1.0.2** |
| `discovery-service` | 2.3.2 | **2.3.8** |
| `event-aggregation-service` | 1.4.13 | **1.5.52** |
| `event-consumer-service` | 1.7.16 | **1.9.6** |
| `envoy-auth-extension` | 2.3.2 | **2.3.3** |
| `storage-navigator` | 0.0.46 | **1.0.1** |
| `storage-api-integration-tests` | 0.7.4 | **1.0.3** |
| `rabbitmq` | 99.3.0 | 99.3.0 (unchanged) |

New known issues documented in this release:
- `FILESERVICE_STATIC_DIR` env var ignored in Kubernetes/Docker deployments — workaround: pass `filesystem --static-dir /data/storage` as container startup args
- IRSA Web Identity Tokens not consumed on EKS — workaround: inject AWS credentials explicitly via K8s secret

New integration test configuration options:
- `skipConnectivityChecks` — bypass preflight health checks
- `serviceIdentity.clientCredentials.*` — explicit OAuth2 client credentials block for authenticated deployments

---

## 1.0.0-beta Initial Release

## 1.0.0-beta Initial Release[\#](#beta-initial-release "Link to this heading")

  - Initial release of the Omniverse Storage APIs and Service Adapters.

  - Added the following APIs: - Discovery - Storage - Permissions - Notifications

  - Added the following Examples - Storage Navigator - Permissions UI - Deployment

</div>

</div>

<div class="prev-next-area">

[**](operations/known-issues.md "previous page")

<div class="prev-next-info">

previous

Known Issues

</div>

[](additional-utilities.md "next page")

<div class="prev-next-info">

next

Additional Utilities

</div>

**

</div>

</div>

<div id="pst-secondary-sidebar" class="bd-sidebar-secondary bd-toc">

<div class="sidebar-secondary-items sidebar-secondary__inner">

<div class="sidebar-secondary-item">

<div id="pst-page-navigation-heading-2" class="page-toc tocsection onthispage">

** On this page

</div>

  - [0.1.0 Initial Release](#initial-release)

</div>

</div>

</div>

</div>

</div>
