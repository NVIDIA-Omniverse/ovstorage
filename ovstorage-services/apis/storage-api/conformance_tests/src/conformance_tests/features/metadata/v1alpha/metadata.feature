Feature: Metadata API

  Background:
    Given a new test namespace called 'metadata_test'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Get metadata from non-existing resource returns appropriate status
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'missing-<protocol>.usd'
    And no object exists at that address
    When calling '<protocol>' get metadata with keys '["author"]' on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | OK               |
      | REST     | 200              |

  Scenario Outline: Get metadata from existing resource with no metadata returns empty result
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'empty-metadata-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' get metadata with keys '["author"]' on that address returns '<return_value>'
    Then the metadata response contains '0' entries
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 200          |

  Scenario Outline: Update metadata on existing resource succeeds and returns ETag
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'update-metadata-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'author' with value 'John Doe' on that address returns '<return_value>'
    Then the metadata response contains an ETag
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 201          |

  Scenario Outline: Update metadata on non-existing resource returns appropriate status
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'missing-update-<protocol>.usd'
    And no object exists at that address
    When calling '<protocol>' update metadata key 'author' with value 'John Doe' on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | OK               |
      | REST     | 201              |

  Scenario Outline: Get metadata after update returns the correct value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'get-after-update-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'author' with value 'Jane Smith' on that address returns '<update_return_value>'
    When calling '<protocol>' get metadata with keys '["author"]' on that address returns '<get_return_value>'
    Then the metadata response contains '1' entries
    And the metadata response contains key 'author' with value 'Jane Smith'
    Examples:
      | protocol | update_return_value | get_return_value |
      | GRPC     | OK                  | OK               |
      | REST     | 201                 | 200              |

  Scenario Outline: Get all metadata using an empty list returns all entries
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'all-keys-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'author' with value 'John Doe' on that address returns '<update_return_value>'
    And calling '<protocol>' update metadata key 'description' with value 'Test file' on that address returns '<update_return_value>'
    When calling '<protocol>' get metadata with keys '[]' on that address returns '<get_return_value>'
    Then the metadata response contains '2' entries
    And the metadata response contains key 'author' with value 'John Doe'
    And the metadata response contains key 'description' with value 'Test file'
    Examples:
      | protocol | update_return_value | get_return_value |
      | GRPC     | OK                  | OK               |
      | REST     | 201                 | 200              |

  Scenario Outline: Delete existing metadata succeeds
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'delete-existing-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'temporary' with value 'delete me' on that address returns '<update_return_value>'
    When calling '<protocol>' delete metadata key 'temporary' on that address returns '<delete_return_value>'
    When calling '<protocol>' get metadata with keys '["temporary"]' on that address returns '<get_return_value>'
    Then the metadata response contains '0' entries
    Examples:
      | protocol | update_return_value | delete_return_value | get_return_value |
      | GRPC     | OK                  | OK                  | OK               |
      | REST     | 201                 | 204                 | 200              |

  Scenario Outline: Delete non-existing metadata succeeds silently
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'delete-missing-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' delete metadata key 'nonexistent' on that address returns '<delete_return_value>'
    Examples:
      | protocol | delete_return_value |
      | GRPC     | OK                  |
      | REST     | 204                 |

  Scenario Outline: Delete metadata from non-existing resource returns appropriate status
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'delete-missing-resource-<protocol>.usd'
    And no object exists at that address
    When calling '<protocol>' delete metadata key 'any' on that address returns '<delete_return_value>'
    Examples:
      | protocol | delete_return_value  |
      | GRPC     | OK                   |
      | REST     | 204                  |

  Scenario Outline: Get specific metadata keys returns only requested keys
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'specific-keys-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'author' with value 'Alice' on that address returns '<update_return_value>'
    And calling '<protocol>' update metadata key 'editor' with value 'Bob' on that address returns '<update_return_value>'
    And calling '<protocol>' update metadata key 'reviewer' with value 'Charlie' on that address returns '<update_return_value>'
    When calling '<protocol>' get metadata with keys '["author", "reviewer"]' on that address returns '<get_return_value>'
    Then the metadata response contains '2' entries
    And the metadata response contains key 'author' with value 'Alice'
    And the metadata response contains key 'reviewer' with value 'Charlie'
    Examples:
      | protocol | update_return_value | get_return_value |
      | GRPC     | OK                  | OK               |
      | REST     | 201                 | 200              |

  Scenario Outline: Update metadata with different data types
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'data-types-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'string_field' with value 'text value' on that address returns '<update_return_value>'
    And calling '<protocol>' update metadata key 'number_field' with 'numeric' value '42' on that address returns '<update_return_value>'
    And calling '<protocol>' update metadata key 'boolean_field' with 'boolean' value 'true' on that address returns '<update_return_value>'
    When calling '<protocol>' get metadata with keys '["string_field", "number_field", "boolean_field"]' on that address returns '<get_return_value>'
    Then the metadata response contains '3' entries
    And the metadata response contains key 'string_field' with value 'text value'
    And the metadata response contains key 'number_field' with numeric value '42'
    And the metadata response contains key 'boolean_field' with boolean value 'true'
    Examples:
      | protocol | update_return_value | get_return_value |
      | GRPC     | OK                  | OK               |
      | REST     | 201                 | 200              |

  Scenario Outline: Metadata operations with invalid resource address return appropriate status
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given an invalid resource address
    When calling '<protocol>' get metadata with keys '["any"]' on that address returns '<get_return_value>'
    And calling '<protocol>' update metadata key 'any' with value 'any' on that address returns '<update_return_value>'
    And calling '<protocol>' delete metadata key 'any' on that address returns '<delete_return_value>'
    Examples:
      | protocol | get_return_value     | update_return_value  | delete_return_value  |
      | GRPC     | INVALID_ARGUMENT     | INVALID_ARGUMENT     | INVALID_ARGUMENT     |
      | REST     | 400                  | 400                  | 400                  |

  Scenario Outline: Conditional update metadata with correct ETag succeeds
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'conditional-update-success-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'author' with value 'Initial Author' on that address returns '<update_return_value>'
    And we memorize the last metadata response as 'initial_update'
    When calling '<protocol>' update metadata key 'author' with value 'Updated Author' using ETag from 'initial_update' on that address returns '<update_return_value>'
    When calling '<protocol>' get metadata with keys '["author"]' on that address returns '<get_return_value>'
    Then the metadata response contains '1' entries
    And the metadata response contains key 'author' with value 'Updated Author'
    Examples:
      | protocol | update_return_value | get_return_value |
      | GRPC     | OK                  | OK               |
      | REST     | 201                 | 200              |

  Scenario Outline: Conditional update metadata with incorrect ETag fails
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'conditional-update-failure-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'author' with value 'Initial Author' on that address returns '<update_return_value>'
    And we memorize the last metadata response as 'initial_update'
    When calling '<protocol>' update metadata key 'author' with value 'Intermediate Author' on that address returns '<update_return_value>'
    When calling '<protocol>' update metadata key 'author' with value 'Final Author' using ETag from 'initial_update' on that address returns '<failed_return_value>'
    When calling '<protocol>' get metadata with keys '["author"]' on that address returns '<get_return_value>'
    Then the metadata response contains '1' entries
    And the metadata response contains key 'author' with value 'Intermediate Author'
    Examples:
      | protocol | update_return_value | failed_return_value  | get_return_value |
      | GRPC     | OK                  | FAILED_PRECONDITION  | OK               |
      | REST     | 201                 | 412                  | 200              |

  Scenario Outline: Conditional delete metadata with correct ETag succeeds
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'conditional-delete-success-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'temporary' with value 'delete me' on that address returns '<update_return_value>'
    And we memorize the last metadata response as 'initial_update'
    When calling '<protocol>' delete metadata key 'temporary' using ETag from 'initial_update' on that address returns '<delete_return_value>'
    When calling '<protocol>' get metadata with keys '["temporary"]' on that address returns '<get_return_value>'
    Then the metadata response contains '0' entries
    Examples:
      | protocol | update_return_value | delete_return_value | get_return_value |
      | GRPC     | OK                  | OK                  | OK               |
      | REST     | 201                 | 204                 | 200              |

  Scenario Outline: Conditional delete metadata with incorrect ETag fails
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    Given a resource address for 'conditional-delete-failure-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' update metadata key 'temporary' with value 'delete me' on that address returns '<update_return_value>'
    And we memorize the last metadata response as 'initial_update'
    When calling '<protocol>' update metadata key 'temporary' with value 'updated value' on that address returns '<update_return_value>'
    When calling '<protocol>' delete metadata key 'temporary' using ETag from 'initial_update' on that address returns '<failed_return_value>'
    When calling '<protocol>' get metadata with keys '["temporary"]' on that address returns '<get_return_value>'
    Then the metadata response contains '1' entries
    And the metadata response contains key 'temporary' with value 'updated value'
    Examples:
      | protocol | update_return_value | failed_return_value  | get_return_value |
      | GRPC     | OK                  | FAILED_PRECONDITION  | OK               |
      | REST     | 201                 | 412                  | 200              |

  Scenario Outline: Update metadata on a resource identity works as well, we do not need to use resource addresses
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'metadata' API in version 'v1alpha' for feature 'metadata'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'metadata-for-identity-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' stat on that address returns '<stat_return_value>'
    Then calling '<protocol>' update metadata key 'key' with value 'value' on the stat result returns '<metadata_return_value>'
    Examples:
      | protocol | stat_return_value  | metadata_return_value |
      | GRPC     | OK                 | OK                    |
      | REST     | 204                | 201                   |
