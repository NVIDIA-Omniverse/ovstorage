Feature: Read() and ReadFromAddress()

  Background:
    Given a new test namespace called 'read_test_beta'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: ReadFromAddress of an available data object returns a valid result
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'readfromaddress-small-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' ReadFromAddress on that address the service returns '<return_value>'
    Then the '<protocol>' result's resource info has size '1024'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 200          |

  Scenario Outline: ReadFromAddress of a non-existing data object returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'missing-<protocol>.usd'
    And no object exists at that address
    Then calling '<protocol>' ReadFromAddress on that address the service returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | NOT_FOUND    |
      | REST     | 404          |

  Scenario Outline: ReadFromAddress of a data object without permissions returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'no_read_permissions-<protocol>.usd'
    And an object exists at that address, but the user has no permissions
    Then calling '<protocol>' ReadFromAddress on that address the service returns '<return_value>'
    Examples:
      | protocol | return_value      |
      | GRPC     | PERMISSION_DENIED |
      | REST     | 403               |

  Scenario Outline: ReadFromAddress with an invalid resource address returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given an invalid resource address
    Then calling '<protocol>' ReadFromAddress on that address the service returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | INVALID_ARGUMENT |
      | REST     | 400              |

  Scenario Outline: ReadFromAddress of a data object with specified download preference works
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'download_preference_at_address-<protocol>-<download_preference>.usd'
    And a test object of size '128' with rand seed '5343421' at that address
    When calling '<protocol>' ReadFromAddress with mode '<download_preference>' downloads the data using the specified preference and it has the correct content for rand seed '5343421'
    Examples:
      | protocol | download_preference |
      | GRPC     | body                |
      | GRPC     | redirect            |
      | REST     | body                |
      | REST     | redirect            |

  Scenario Outline: Read of an available data object returns a valid result
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'read-small-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' Stat on that address returns '<stat_return_value>'
    Then calling '<protocol>' Read on that response returns '<read_return_value>'
    And the '<protocol>' result's resource info has size '1024'
    Examples:
      | protocol | read_return_value | stat_return_value |
      | GRPC     | OK                | OK                |
      | REST     | 200               | 204               |

  Scenario Outline: Read of a data object via a resource identity returns the appropriate status code when the data object is permanently no longer available.
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'to_be_deleted-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' Stat on that address returns '<stat_return_value>'
    And the object referenced by that resource address is permanently deleted
    Then calling '<protocol>' Read on that response returns '<read_return_value>'
    Examples:
      | protocol | read_return_value | stat_return_value |
      | GRPC     | NOT_FOUND         | OK                |
      | REST     | 404               | 204               |

  Scenario Outline: Read of a data object without permissions returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'read_permissions_removed-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' Stat on that address returns '<stat_return_value>'
    And the user loses read permissions on that object
    Then calling '<protocol>' Read on that response returns '<read_return_value>'
    Examples:
      | protocol | read_return_value | stat_return_value |
      | GRPC     | PERMISSION_DENIED | OK                |
      | REST     | 403               | 204               |

  Scenario Outline: Read with an invalid resource identity returns the appropriate status code
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given an invalid resource identity
    Then calling '<protocol>' Read on that resource identity returns '<read_return_value>'
    Examples:
      | protocol | read_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |

  Scenario Outline: Read of a data object with specified download preference works
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'download_preference-<protocol>-<download_preference>.usd'
    And a test object of size '64' with rand seed '387465' at that address
    When calling '<protocol>' Stat on that address returns '<stat_return_value>'
    Then calling '<protocol>' Read with mode '<download_preference>' downloads the data using the specified preference and it has the correct content for rand seed '387465'
    Examples:
      | protocol | download_preference | stat_return_value |
      | GRPC     | body                | OK                |
      | GRPC     | redirect            | OK                |
      | REST     | body                | 204               |
      | REST     | redirect            | 204               |
