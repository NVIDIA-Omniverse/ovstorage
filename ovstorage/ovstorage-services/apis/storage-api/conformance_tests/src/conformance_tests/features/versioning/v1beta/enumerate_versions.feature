Feature: EnumerateVersions()

  Background:
    Given a new test namespace called 'enumerate_versions_test_beta'
    And a connection to the storage service
    And an authenticated user
    And a new test namespace called 'enumerate-test-beta'

  Scenario Outline: EnumerateVersions of a data object before and after adding a new version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for '<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    And the EnumerateVersions returned '1' items
    When calling '<protocol>' write on that address with data returns a created response
    And calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
    Then the EnumerateVersions returned '2' items
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
    And the '<protocol>' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'write'
    Given a resource address for 'missing-<protocol>.usd'
    And no object exists at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<return_value>'
  Examples:
    | protocol | return_value |
    | GRPC     | NOT_FOUND    |
    | REST     | 404          |

  Scenario: EnumerateVersions of data object using GRPC with lots of versions is possible as well
    Given the service speaks 'GRPC'
    And the 'GRPC' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
    And the 'GRPC' service supports the 'fileobject' API in version 'v1beta' for feature 'write'
    Given a resource address for 'many-versions-GRPC.usd'
    And '250' versions with distinct sizes from '2' to '500' bytes exist at that address
    And we add a version of size '502' with rand seed '1' at that address
    When calling 'GRPC' EnumerateVersions exhaustively on that address returns 'OK'
    Then the EnumerateVersions returned '251' items
    And the latest item returned by EnumerateVersions has size '502'
    And all expected version sizes are present in the EnumerateVersions result

  Scenario: EnumerateVersions of data object using REST with lots of versions is possible as well
    Given the service speaks 'REST'
    And the 'REST' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
    And the 'REST' service supports the 'fileobject' API in version 'v1beta' for feature 'write'
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
#  Scenario: EnumerateVersions with medium-sized files using REDIRECT upload path (GRPC)
#    Given the service speaks 'GRPC'
#    And the 'GRPC' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
#    And the 'GRPC' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
#    Given a resource address for 'many-versions-redirect-GRPC.usd'
#    And '20' versions with distinct sizes using 'redirect' upload exist at that address using 'GRPC'
#    When calling 'GRPC' EnumerateVersions exhaustively on that address returns 'OK'
#    Then the EnumerateVersions returned '20' items
#    And all expected version sizes are present in the EnumerateVersions result
#
#  Scenario: EnumerateVersions with medium-sized files using REDIRECT upload path (REST)
#    Given the service speaks 'REST'
#    And the 'REST' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
#    And the 'REST' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
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
#    And the 'GRPC' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
#    And the 'GRPC' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
#    Given a resource address for 'many-versions-multipart-GRPC.usd'
#    And '5' versions with distinct sizes using 'multipart' upload exist at that address using 'GRPC'
#    When calling 'GRPC' EnumerateVersions exhaustively on that address returns 'OK'
#    Then the EnumerateVersions returned '5' items
#    And all expected version sizes are present in the EnumerateVersions result
#
#  @optional
#  Scenario: EnumerateVersions with large files using MULTIPART upload path (REST)
#    Given the service speaks 'REST'
#    And the 'REST' service supports the 'versioning' API in version 'v1beta' for feature 'versioning'
#    And the 'REST' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
#    Given a resource address for 'many-versions-multipart-REST.usd'
#    And '5' versions with distinct sizes using 'multipart' upload exist at that address using 'REST'
#    When calling 'REST' EnumerateVersions exhaustively on that address returns '200'
#    Then the EnumerateVersions returned '5' items
#    And all expected version sizes are present in the EnumerateVersions result
