# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.3] - 2025-12-03

### Added
- Improved OpenAPI spec

## [1.5.1] - 2025-12-02

### Added
- Added "previous_filter_groups" field to the gRPC and REST consume-non-durable APIs for improved functionality around updating filter groups

## [1.4.11] - 2025-11-06

### Added
- Improved OpenAPI specification

## [1.4.10] - 2025-11-06

### Added
- Fixed case of filter_type fields in REST API
- Added Java annotations and golang package names to proto files

## [1.4.9] - 2025-10-31

### Added
- Security improvements
- Better documentation in .proto and openapi.yaml files

## [1.4.2] - 2025-10-24

### Added
- gRPC API for consuming events
- REST API with Server-Sent Events (SSE) support for event streaming 
- REST API OpenAPI documentation
- API support for both durable and non-durable queue consumption
