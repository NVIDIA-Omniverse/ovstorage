Feature: EnumerateVersions()

  Background:
    Given a new test namespace called 'enumerate_versions_test_alpha'
    And a connection to the storage service
    And an authenticated user
    And a new test namespace called 'enumerate-test-alpha'

  Scenario Outline: EnumerateVersions of a data object before and after adding a new version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for '<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    And the EnumerateVersions returned '1' items
    When calling '<protocol>' write on that address with data returns a created response
    And calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    And the EnumerateVersions returned '2' items
  Examples:
    | protocol | return_value      |
    | GRPC     | OK                |
    | REST     | 200               |

# Commented this out - deleting individual versions is not possible with the proposed delete API
# You can only delete with a resource_address, which would remove all versions or mark all versions with a
# tombstone

#  Scenario Outline: EnumerateVersions of data object before and after deleting one of its versions
#    Given a resource address for '<protocol>.usd'
#    And an object of size '1024' exists at that address and is readable and has 2 versions
#    When calling '<protocol>' write on that address with data returns a created response
#    When invoking  '<protocol>' EnumerateVersions on that address
#    Then the service returns '<return_value>'
#    And the result's items' size is '2'
#    When deleting one of the versions of that object
#    And invoking  '<protocol>' EnumerateVersions again on that same address
#    Then the service returns '<return_value>'
#    And the result's items' size is '1'
#  Examples:
#    | protocol | return_value      |
#    | GRPC     | OK                |
#    | REST     | 200               |

  Scenario Outline: EnumerateVersions of a non-existing data object returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'write'
    Given a resource address for 'missing-<protocol>.usd'
    And no object exists at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
  Examples:
    | protocol | return_value |
    | GRPC     | NOT_FOUND    |
    | REST     | 404          |

  Scenario: EnumerateVersions of data object using GRPC with lots of versions is possible as well
    Given the service speaks 'GRPC'
    And the 'GRPC' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the 'GRPC' service supports the 'fileobject' API in version 'v1alpha' for feature 'write'
    Given a resource address for 'many-versions-GRPC.usd'
    And '250' versions with distinct sizes from '2' to '500' bytes exist at that address
    And we add a version of size '502' with rand seed '1' at that address
    When calling 'GRPC' EnumerateVersions exhaustively on that address returns 'OK'
    Then the EnumerateVersions returned '251' items
    And the latest item returned by EnumerateVersions has size '502'
    And all expected version sizes are present in the EnumerateVersions result

  Scenario: EnumerateVersions of data object using REST with lots of versions is possible as well
    Given the service speaks 'REST'
    And the 'REST' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the 'REST' service supports the 'fileobject' API in version 'v1alpha' for feature 'write'
    Given a resource address for 'many-versions-REST.usd'
    And '250' versions with distinct sizes from '2' to '500' bytes exist at that address
    And we add a version of size '502' with rand seed '1' at that address
    When calling 'REST' EnumerateVersions exhaustively on that address returns '200'
    #When calling 'REST' EnumerateVersions exhaustively with page size '50' on that address returns '200'
    Then the EnumerateVersions returned '251' items
    And the latest item returned by EnumerateVersions has size '502'
    And all expected version sizes are present in the EnumerateVersions result

  # The next section is disabled until we get a proper 503 back-off handling in the test upload, else
  # they will fail on real S3.
  # Test REDIRECT upload path for ghost write detection (size determined by service)
  # Scenario: EnumerateVersions with medium-sized files using REDIRECT upload path (GRPC)
#    Given the service speaks 'GRPC'
#    And the 'GRPC' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
#    And the 'GRPC' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
#    Given a resource address for 'many-versions-redirect-GRPC.usd'
#    And '20' versions with distinct sizes using 'redirect' upload exist at that address using 'GRPC'
#    When calling 'GRPC' EnumerateVersions exhaustively on that address returns 'OK'
#    Then the EnumerateVersions returned '20' items
#    And all expected version sizes are present in the EnumerateVersions result
#
#  Scenario: EnumerateVersions with medium-sized files using REDIRECT upload path (REST)
#    Given the service speaks 'REST'
#    And the 'REST' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
#    And the 'REST' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
#    Given a resource address for 'many-versions-redirect-REST.usd'
#    And '20' versions with distinct sizes using 'redirect' upload exist at that address using 'REST'
#    When calling 'REST' EnumerateVersions exhaustively on that address returns '200'
#    Then the EnumerateVersions returned '20' items
#    And all expected version sizes are present in the EnumerateVersions result
#
#  # Test MULTIPART upload path for ghost write detection (size determined by service)
#  @optional
#  Scenario: EnumerateVersions with large files using MULTIPART upload path (GRPC)
#    Given the service speaks 'GRPC'
#    And the 'GRPC' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
#    And the 'GRPC' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
#    Given a resource address for 'many-versions-multipart-GRPC.usd'
#    And '5' versions with distinct sizes using 'multipart' upload exist at that address using 'GRPC'
#    When calling 'GRPC' EnumerateVersions exhaustively on that address returns 'OK'
#    Then the EnumerateVersions returned '5' items
#    And all expected version sizes are present in the EnumerateVersions result
#
#  @optional
#  Scenario: EnumerateVersions with large files using MULTIPART upload path (REST)
#    Given the service speaks 'REST'
#    And the 'REST' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
#    And the 'REST' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
#    Given a resource address for 'many-versions-multipart-REST.usd'
#    And '5' versions with distinct sizes using 'multipart' upload exist at that address using 'REST'
#    When calling 'REST' EnumerateVersions exhaustively on that address returns '200'
#    Then the EnumerateVersions returned '5' items
#    And all expected version sizes are present in the EnumerateVersions result

  Scenario Outline: EnumerateVersions of a data object with multiple versions might provide valid resource addresses for ReadFromAddress
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'read-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    And we add a version of size '512' with rand seed '123' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    Then the EnumerateVersions returned '3' items
    When memorizing the resource address with index '-1' from EnumerateVersions as 'newest_version_address'
    And memorizing the resource address with index '0' from EnumerateVersions as 'oldest_version_address'
    And calling '<protocol>' ReadFromAddress on memorized 'newest_version_address'
    Then the '<protocol>' call should return '<return_value>'
    And the '<protocol>' result's resource info has size '512'
    When calling '<protocol>' ReadFromAddress on memorized 'oldest_version_address'
    Then the '<protocol>' call should return '<return_value>'
    And the '<protocol>' result's resource info has size '1024'
  Examples:
    | protocol | return_value      |
    | GRPC     | OK                |
    | REST     | 200               |

  Scenario Outline: EnumerateVersions of a data object with multiple versions might provide valid resource addresses, but they cannot be used for EnumerateVersions
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'read-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    Then the EnumerateVersions returned '2' items
    Given  a resource address from EnumerateVersions with index '0'
    Then calling '<protocol>' EnumerateVersions exhaustively on that address returns '<error_return_value>'
  Examples:
    | protocol | return_value      | error_return_value |
    | GRPC     | OK                | INVALID_ARGUMENT   |
    | REST     | 200               | 400                |

  Scenario Outline: EnumerateVersions of a data object with multiple versions might provide valid resource addresses, but they cannot be used for List or ListStat
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    Given a resource address for 'read-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    Then the EnumerateVersions returned '2' items
    Given  a resource address from EnumerateVersions with index '0'
    Then calling '<protocol>' List exhaustively on that address returns '<error_return_value>'
    And calling '<protocol>' ListStat exhaustively on that address returns '<error_return_value>'
  Examples:
    | protocol | return_value      | error_return_value |
    | GRPC     | OK                | INVALID_ARGUMENT   |
    | REST     | 200               | 400                |

  Scenario Outline: EnumerateVersions of a data object with multiple versions, then stat the second newest version using Stat
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'stat-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    And we add a version of size '512' with rand seed '123' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<enumerate_return_value>'
    Then the EnumerateVersions returned '3' items
    When memorizing the resource address with index '1' from EnumerateVersions as 'first_version_address'
    Then calling '<protocol>' stat on memorized 'first_version_address' returns '<stat_return_value>'
    And the '<protocol>' result's resource info has size '2048'
  Examples:
    | protocol | enumerate_return_value | stat_return_value |
    | GRPC     | OK                     | OK                |
    | REST     | 200                    | 204               |

  Scenario Outline: EnumerateVersions of a data object with single version, then read it using ReadFromAddress with download preference
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'single-version-<protocol>-<download_preference>.usd'
    And a test object of size '256' with rand seed '999' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    Then the EnumerateVersions returned '1' items
    When memorizing the resource address with index '0' from EnumerateVersions as 'only_version_address'
    Then calling '<protocol>' ReadFromAddress with mode '<download_preference>' on memorized 'only_version_address' downloads the data using the specified preference and it has the correct content for rand seed '999'
  Examples:
    | protocol | return_value | download_preference |
    | GRPC     | OK           | body                |
    | GRPC     | OK           | redirect            |
    | REST     | 200          | body                |
    | REST     | 200          | redirect            |

  Scenario Outline: EnumerateVersions of a data object with multiple versions, then attempt to delete a specific version should fail, but delete all of them works
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'delete-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    And we add a version of size '512' with rand seed '123' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<enumerate_return_value>'
    Then the EnumerateVersions returned '3' items
    When memorizing the resource address with index '0' from EnumerateVersions as 'version_address_to_delete'
    Then calling '<protocol>' delete with memorized 'version_address_to_delete' returns '<delete_return_value>'
    When memorizing the resource address with index '-1' from EnumerateVersions as 'version_address_to_delete'
    Then calling '<protocol>' delete with memorized 'version_address_to_delete' returns '<delete_return_value>'
    When calling '<protocol>' delete on that address returns '<successful_delete_return_value>'
  Examples:
    | protocol | enumerate_return_value | delete_return_value | successful_delete_return_value |
    | GRPC     | OK                     | INVALID_ARGUMENT    | OK                             |
    | REST     | 200                    | 400                 | 204                            |

  # Scenario Outline: EnumerateVersions of a data object with multiple versions, then deleting that data object, should be possible to ReadFromAddress if storage supports soft-delete
  # We can't know if the implementation supports soft-delete or not. Capabilities API should be improved to support this, then this test can be implemented.

  Scenario Outline: EnumerateVersions of a data object with multiple versions, then attempt to write to a specific version should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'write-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    And we add a version of size '512' with rand seed '123' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<enumerate_return_value>'
    Then the EnumerateVersions returned '3' items
    When memorizing the resource address with index '-1' from EnumerateVersions as 'version_address_to_write'
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    Then calling '<protocol>' write on memorized 'version_address_to_write' with data returns '<write_return_value>'
  Examples:
    | protocol | enumerate_return_value | write_return_value |
    | GRPC     | OK                     | INVALID_ARGUMENT   |
    | REST     | 200                    | 400                |


  Scenario Outline: EnumerateVersions might produce resource addresses, but they cannot be enumerated or used for fetchwritetypeinfo
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'enumerate-versioned-address-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<enumerate_versions_return_value>'
    Then the EnumerateVersions returned '2' items
    Given a resource address from EnumerateVersions with index '0'
    Then calling '<protocol>' Enumerate exhaustively on that address returns '<error_return_value>'
    And calling '<protocol>' FetchWriteTypeInfo on that address returns '<error_return_value>'
  Examples:
    | protocol | enumerate_versions_return_value | error_return_value |
    | GRPC     | OK                              | INVALID_ARGUMENT   |
    | REST     | 200                             | 400                |
