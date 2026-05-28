Feature: FetchWriteTypeInfo()


  Background:
    Given a new test namespace called 'fetch_write_type_info_test_beta'
    And a connection to the storage service
    And an authenticated user


  Scenario Outline: FetchWriteTypeInfo returns valid write type intervals for existing address
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And a resource address for 'test-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' FetchWriteTypeInfo on that address returns '<return_value>'
    Then the response contains at least one write type interval
    And all write type intervals have valid size ranges
    And all write type intervals have valid upload preferences
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 200          |

  Scenario Outline: FetchWriteTypeInfo returns valid intervals for non-existing address
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And a resource address for 'missing-<protocol>.usd'
    And no object exists at that address
    When calling '<protocol>' FetchWriteTypeInfo on that address returns '<return_value>'
    Then the response contains at least one write type interval
    And all write type intervals have valid size ranges
    And all write type intervals have valid upload preferences
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 200          |

  Scenario Outline: FetchWriteTypeInfo intervals have no gaps
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And a resource address for 'ranges-<protocol>.usd'
    When calling '<protocol>' FetchWriteTypeInfo on that address returns '<return_value>'
    Then the response contains at least one write type interval
    And all write type intervals have valid size ranges
    Then no gaps exist between consecutive intervals
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 200          |

  Scenario Outline: FetchWriteTypeInfo supports zero-sized writes
  Given the service speaks '<protocol>'
  And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
  And a resource address for 'zero-sized-<protocol>.usd'
  When calling '<protocol>' FetchWriteTypeInfo on that address returns '<return_value>'
  Then the response supports zero-sized writes
  Examples:
    | protocol | return_value |
    | GRPC     | OK           |
    | REST     | 200          |