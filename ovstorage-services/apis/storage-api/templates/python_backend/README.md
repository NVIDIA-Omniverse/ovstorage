# Python Backend Template

This directory contains a template for creating a new storage backend for the Omniverse Storage API Python service.

## Quick Start

1. **Copy this template** to `filesystem_example/src/local_filesystem_service/your_backend_name/`

2. **Rename files and classes** - Replace `MyStorage` with your storage system name

3. **Implement the methods** in `my_storage_provider.py` (see comments for guidance)

4. **Register CLI options** in `__init__.py`

5. **Add import** to `filesystem_example/src/local_filesystem_service/backends/__init__.py`:
   ```python
   from local_filesystem_service.your_backend_name import my_storage_provider
   ```

6. **Test it**:
   ```bash
   cd filesystem_example
   poetry install
   source .venv/bin/activate
   local-filesystem-service your_backend --help
   local-filesystem-service your_backend [options]
   ```

7. **Run conformance tests**:
   ```bash
   cd conformance_tests
   source .venv/bin/activate
   run-conformance-tests
   ```

## Files

- `__init__.py` - Package init and CLI registration
- `my_storage_provider.py` - Main implementation (THE FILE TO EDIT)

## Implementation Tips

### Start Simple
Implement basic methods first:
1. `base_uri`, `is_address_valid()`
2. `exists()`, `is_file()`, `is_dir()`
3. `stat()` - this is heavily tested
4. `read_from_address()`, `write_version()`
5. Then add the rest incrementally

### Resource Identity Design
Your resource identity should encode everything needed to retrieve a specific version:
- Storage-specific location info
- Version identifier

Make it opaque (base64) so clients don't try to parse it.

### Error Handling
The conformance tests check specific error conditions. Make sure to:
- Return `NOT_FOUND`/404 for missing resources
- Return `PERMISSION_DENIED`/403 for access denied
- Return `INVALID_ARGUMENT`/400 for bad addresses
- Return appropriate errors for folder vs file operations

### Versioning
If your storage doesn't have native versioning:
- You can create a separate version store
- Or use a versioning scheme like `key.v1`, `key.v2`
- Or disable versioning (implement `enumerate_versions` to return single version)
