Feature: Delete()

  Background:
    Given a new test namespace called 'delete_test_alpha'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Delete an existing file
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'file-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    When calling '<protocol>' delete on that address returns '<delete_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | delete_return_value | stat_return_value |
      | GRPC     | OK                  | NOT_FOUND         |
      | REST     | 204                 | 404               |

  Scenario Outline: Delete a nonexistent file
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'nonexistent-<protocol>.txt'
    And no object exists at that address
    When calling '<protocol>' delete on that address returns '<delete_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | delete_return_value | stat_return_value |
      | GRPC     | OK                  | NOT_FOUND         |
      | REST     | 204                 | 404               |

  @optional
  Scenario Outline: Delete a file if the specified resource_identity matches with previous_version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports optimistic locking for 'delete'
    Given a resource address for 'file_with_headversion-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable and has '2' versions
    And determining head resource identity with '<protocol>'
    When calling '<protocol>' delete on that address with previous version returns '<delete_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | delete_return_value | stat_return_value |
      | GRPC     | OK                  | NOT_FOUND         |
      | REST     | 204                 | 404               |

  @optional
  Scenario Outline: Delete a file if the specified resource_identity doesn't match with previous_version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports optimistic locking for 'delete'
    Given a resource address for 'file1-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable and has '2' versions
    And determining the second latest resource identity with '<protocol>'
    When calling '<protocol>' delete on that address with previous version returns '<delete_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | delete_return_value | stat_return_value |
      | GRPC     | FAILED_PRECONDITION | OK                |
      | REST     | 412                 | 204               |

  @optional
  Scenario Outline: Delete a file if the specified resource_identity is other file's previous_version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports optimistic locking for 'delete'
    Given a resource address for 'file2-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    When determining another object's resource identity with '<protocol>'
    And calling '<protocol>' delete on that address with previous version returns '<delete_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | delete_return_value | stat_return_value |
      | GRPC     | FAILED_PRECONDITION | OK                |
      | REST     | 412                 | 204               |

  Scenario Outline: Deleting a file from folder
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    Given a resource address 'delete-in-folder-<protocol>' which is enumerable
    And '2' objects within that address of size '64'
    When calling '<protocol>' List exhaustively on that address returns '<list_return_value>'
    And memorizing single file address from listed entries as 'address_to_delete'
    Then calling '<protocol>' delete with memorized 'address_to_delete' returns '<delete_return_value>'
    And calling '<protocol>' List exhaustively on that address returns '<list_return_value>'
    And the number of returned list entries is '1'
    Examples:
      | protocol | list_return_value | delete_return_value |
      | GRPC     | OK                | OK                  |
      | REST     | 200               | 204                 |

  Scenario Outline: Deleting a file from resource address within an enumerable address
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address 'delete-in-enumerable-<protocol>' which is enumerable
    And '2' objects within that address of size '64'
    When calling '<protocol>' Enumerate exhaustively on that address returns '<list_return_value>'
    And memorizing the resource address with index '1' from Enumerate as 'address_to_delete'
    Then calling '<protocol>' delete with memorized 'address_to_delete' returns '<delete_return_value>'
    And calling '<protocol>' Enumerate exhaustively on that address returns '<list_return_value>'
    And there is only '1' entry left at that address
    Examples:
      | protocol | list_return_value | delete_return_value |
      | GRPC     | OK                | OK                  |
      | REST     | 200               | 204                 |
