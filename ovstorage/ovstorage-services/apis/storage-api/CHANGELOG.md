# 1.0.0-beta.4

* Improved local filesystem example startup defaults so backend environment variables (including `FILESERVICE_STATIC_DIR`) are honored when no backend subcommand is provided.
* Updated local filesystem example Docker defaults and documentation to keep backend startup behavior consistent.
* Improved REST conformance tests for compatibility with newer FastAPI behavior, including metadata request handling and write/upload flow checks.
* Updated documentation and OSS release packaging to include both `v1beta` and `v1alpha` API specifications.

# 1.0.0-beta.2

* Added a reference implementation of the Storage API using Python and the local filesystem as an example.
* Added a conformance test suite documenting behavioral expectations of any Storage API implementation using Gherkin BDD,
and a runnable implementation in Python that can be used to test any storage service for specification adherence.
* Now including a v1alpha channel as a preview of functions that might make it into v1beta.
  * The FileObjectService support copy and move in the v1alpha version.
  * The FileFolderService supports CreateFolder and GetFolderMode in v1alpha, allowing for different handling of empty folders to be exposed by a service implementation.
  * The CapabilitiesService got an additional function, ListRoutes, that can be used  in setups with more than one storage service instance serving different resource addresses.
  * The VersioningService adds experimental support for versioned resource addresses in addition to resource identities.
  * Added a new MetadataService in v1alpha, which can be used to store arbitrary metadata on resource addresses or resource identities. 

# 1.0.0-beta.1

Initial closed availability release.
