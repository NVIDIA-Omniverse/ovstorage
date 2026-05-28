Feature: Stat()

  Background:
    Given a new test namespace called 'stat_test_beta'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Stat of an available data object returns a valid result
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'small-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' stat on that address returns '<return_value>'
    Then the '<protocol>' result's resource info has size '1024'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 204          |

  Scenario Outline: Stat of a non-existing data object returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'missing-<protocol>.usd'
    And no object exists at that address
    Then calling '<protocol>' stat on that address returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | NOT_FOUND    |
      | REST     | 404          |

Scenario: GRPC Stat of an enumerable address (folder) returns the appropriate status code
    Given the service speaks 'GRPC'
    And the 'GRPC' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address 'folder-empty-grpc' which is enumerable
    Then calling 'GRPC' Enumerate exhaustively on that address returns 'NOT_FOUND'
    Then calling 'GRPC' stat on that address returns 'NOT_FOUND'

Scenario: REST Stat of an enumerable address (folder) returns the appropriate status code
    Given the service speaks 'REST'
    And the 'REST' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address 'folder-empty-rest' which is enumerable
    Then calling 'REST' Enumerate exhaustively with page size '50' on that address returns '404'
    Then calling 'REST' stat on that address returns '404'

Scenario Outline: Stat of an enumerable address (folder) that is not empty returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address 'folder-<protocol>' which is enumerable
    And an object of size '24' within that address which is named 'not_empty.usd'
    Then calling '<protocol>' stat on that address returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | NOT_FOUND    |
      | REST     | 404          |

  Scenario Outline: Stat of a data object without permissions returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'no_read_permissions-<protocol>.usd'
    And an object exists at that address, but the user has no permissions
    Then calling '<protocol>' stat on that address returns '<return_value>'
    Examples:
      | protocol | return_value      |
      | GRPC     | PERMISSION_DENIED |
      | REST     | 403               |

  Scenario Outline: Stat with an invalid resource address returns appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given an invalid resource address
    Then calling '<protocol>' stat on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | INVALID_ARGUMENT |
      | REST     | 400              |

  Scenario Outline: Stat after modification of a data object returns a different resource identity
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'modify_me-<protocol>.usd'
    And a test object of size '64' with rand seed '1234' at that address
    When calling '<protocol>' stat on that address returns '<return_value>'
    And we memorize the last response as 'first_stat'
    And we wait for '5.0' seconds
    And we add a version of size '64' with rand seed '4321' at that address
    Then calling '<protocol>' stat on that address returns '<return_value>'
    And the resource identity returned is different from the one in the memorized response 'first_stat'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 204          |
