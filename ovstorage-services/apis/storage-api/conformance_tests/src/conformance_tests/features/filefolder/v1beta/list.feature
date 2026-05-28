Feature: List() and ListStat(), FileFolderAPI

  Background:
    Given a new test namespace called 'liststat_test_beta'
    And a connection to the storage service
    And an authenticated user


  Scenario Outline: List and ListStat of a non-existent resource address return the correct error value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address '<protocol>_<method>_non_existent_folder<suffix>' which is enumerable
    And no object exists at that address
    Then calling '<protocol>' <method> exhaustively on that address returns '<return_value>'
    Examples:
      | protocol | method   | return_value | suffix |
      | GRPC     | List     | NOT_FOUND    |        |
      | REST     | List     | 404          |        |
      | REST     | ListStat | 404          |        |
      | GRPC     | ListStat | NOT_FOUND    |        |
      | GRPC     | List     | NOT_FOUND    | /      |
      | REST     | List     | 404          | /      |
      | REST     | ListStat | 404          | /      |
      | GRPC     | ListStat | NOT_FOUND    | /      |


  Scenario Outline: List and ListStat of a data object's resource address fails because data objects cannot be listed
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address for '<protocol>_<method>_file.txt'
    And an object of size '1024' exists at that address and is readable
    Then calling '<protocol>' <method> exhaustively on that address returns '<return_value>'
    Examples:
      | protocol | method   | return_value     |
      | GRPC     | ListStat | NOT_FOUND        |
      | REST     | ListStat | 404              |
      | GRPC     | List     | NOT_FOUND        |
      | REST     | List     | 404              |


  Scenario Outline: List and ListStat work on a root resource address as well
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a root resource address which has some content
    Then calling '<protocol>' <method> exhaustively on that address returns '<return_value>'
    Examples:
      | protocol | method   | return_value     |
      | GRPC     | ListStat | OK               |
      | REST     | ListStat | 200              |
      | GRPC     | List     | OK               |
      | REST     | List     | 200              |

  Scenario Outline: List and ListStat of a directory-like resource address using GRPC with lots of entries works
    Given the service speaks 'GRPC'
    And the 'GRPC' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the 'GRPC' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address 'GRPC_List_large_folder<suffix>' which is enumerable
    And no object exists at that address
    And '23' objects within that address of size '64'
    When calling 'GRPC' List exhaustively on that address returns 'OK'
    Then the number of returned list entries is '23'
    Then calling 'GRPC' ListStat exhaustively on that address returns 'OK'
    And the number of returned liststat entries is '23' and each has size '64'
  Examples:
      | suffix |
      |        |
      | /      |


  Scenario Outline: List and ListStat of a directory-like resource address using REST with lots of entries works
    Given the service speaks 'REST'
    And the 'REST' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the 'REST' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address 'REST_ListStat_or_List_large_folder<suffix>' which is enumerable
    And no object exists at that address
    And '16' objects within that address of size '64'
    Then calling 'REST' List exhaustively with page size '5' on that address returns '200'
    And the number of returned list entries is '16'
    Then calling 'REST' ListStat exhaustively with page size '5' on that address returns '200'
    And the number of returned liststat entries is '16' and each has size '64'
  Examples:
      | suffix |
      |        |
      | /      |


  Scenario Outline: List and ListStat of a directory-like resource address using REST with paginated entries works
    Given the service speaks 'REST'
    And the 'REST' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the 'REST' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address 'REST_List_or_ListStat_large_folder<suffix>' which is enumerable
    And no object exists at that address
    And '3' objects within that address of size '64'
    When calling 'REST' List exhaustively with page size '5' on that address returns '200'
    And the number of returned list entries is '3'
    And a continuation token is null after the second page for List
    When calling 'REST' ListStat exhaustively with page size '5' on that address returns '200'
    And the number of returned liststat entries is '3' and each has size '64'
    And a continuation token is null after the second page for ListStat
  Examples:
      | suffix |
      |        |
      | /      |


  Scenario Outline: List of a subtree works and respects folder delimiter
    Given the service speaks '<method>'
    And the '<method>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<method>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address 'List_folder_<method><suffix>' which is enumerable
    And no object exists at that address
    And an object of size '1024' within that address which is named 'file1.txt'
    And an object of size '65536' within that address which is named 'file2.txt'
    And an object of size '11' within that address which is named 'subfolder1/dummy.txt'
    And an object of size '11' within that address which is named 'subfolder2/dummy.txt'
    When calling '<method>' List exhaustively on that address returns '<return_value>'
    Then one of the files returned by List is called 'file1.txt'
    And one of the files returned by List is called 'file2.txt'
    And one of the folders returned by List is called 'subfolder1'
    And one of the folders returned by List is called 'subfolder2'
    And all items returned by '<method>' List have valid resource addresses and Stat()/List() on them return '<stat_return_value>/<list_return_value>' respectively
  Examples:
    | method | return_value | suffix | stat_return_value | list_return_value |
    | GRPC   | OK           |        | OK                | OK                |
    | REST   | 200          |        | 204               | 200               |
    | GRPC   | OK           | /      | OK                | OK                |
    | REST   | 200          | /      | 204               | 200               |

  Scenario Outline: ListStat a subtree works and allows access to the metadata of the items in it and respects folder delimiter
    Given the service speaks '<method>'
    And the '<method>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<method>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address 'ListStat_folder_<method><suffix>' which is enumerable
    And no object exists at that address
    And an object of size '1024' within that address which is named 'file1.txt'
    And an object of size '65536' within that address which is named 'file2.txt'
    And an object of size '10' within that address which is named 'subfolder1/dummy.txt'
    And an object of size '10' within that address which is named 'subfolder2/dummy.txt'
    When calling '<method>' ListStat exhaustively on that address returns '<return_value>'
    Then one of the items returned by ListStat is called 'file1.txt' and has size '1024'
    And one of the items returned by ListStat is called 'file2.txt' and has size '65536'
    Then one of the folders returned by ListStat is called 'subfolder1'
    And one of the folders returned by ListStat is called 'subfolder2'
    And all items returned by '<method>' ListStat have valid resource addresses and Stat()/List() on them return '<stat_return_value>/<list_return_value>' respectively
  Examples:
    | method | return_value | suffix | stat_return_value | list_return_value |
    | GRPC   | OK           |        | OK                | OK                |
    | REST   | 200          |        | 204               | 200               |
    | GRPC   | OK           | /      | OK                | OK                |
    | REST   | 200          | /      | 204               | 200               |
