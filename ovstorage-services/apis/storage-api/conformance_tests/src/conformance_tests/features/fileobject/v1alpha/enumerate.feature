Feature: Enumerate()

  Background:
    Given a new test namespace called 'enumerate_test_alpha'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Enumerate of a data object's resource address fails because data objects cannot be enumerated
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'small-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    Then calling '<protocol>' Enumerate exhaustively on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | NOT_FOUND        |
      | REST     | 404              |

  Scenario Outline: Enumerate of an enumerable resource address without content fails like list() does
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address 'empty-enumerate-<protocol>' which is enumerable
    Then calling '<protocol>' Enumerate exhaustively on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | NOT_FOUND        |
      | REST     | 404              |

  Scenario Outline: Enumerate a directory-like resource address allows to access the metadata of the items in there
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address 'folder-<protocol>' which is enumerable
    And an object of size '1024' within that address which is named 'small.usd'
    And an object of size '65536' within that address which is named 'larger.usd'
    Then calling '<protocol>' Enumerate exhaustively on that address returns '<return_value>'
    And one of the items returned by Enumerate is called 'small.usd' and has size '1024'
    And one of the items returned by Enumerate is called 'larger.usd' and has size '65536'
    And all items returned by '<protocol>' Enumerate have valid resource addresses and Stat() on them returns '<stat_return>'
    Examples:
      | protocol | return_value | stat_return |
      | GRPC     | OK           | OK          |
      | REST     | 200          | 204         |

  Scenario Outline: Enumerating a root resource address allows to access the metadata of the items in there
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a root resource address which has some content
    Then calling '<protocol>' Enumerate for max '50' items on that address returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 200          |

  Scenario: Enumerate a directory-like resource address using GRPC with lots of entries is possible as well
    Given the service speaks 'GRPC'
    And the 'GRPC' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address 'large_folder-GRPC' which is enumerable
    And '257' objects within that address of size '64'
    Then calling 'GRPC' Enumerate exhaustively on that address returns 'OK'
    And the number of returned enumerate entries is '257'

  Scenario: Enumerate a directory-like resource address using REST with lots of entries is possible as well
    Given the service speaks 'REST'
    And the 'REST' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address 'large_folder-REST' which is enumerable
    And '257' objects within that address of size '64'
    Then calling 'REST' Enumerate exhaustively with page size '50' on that address returns '200'
    And the number of returned enumerate entries is '257'
