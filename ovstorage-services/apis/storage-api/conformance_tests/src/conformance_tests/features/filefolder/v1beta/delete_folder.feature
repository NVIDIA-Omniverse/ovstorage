Feature: DeleteFolder(), FileFolderAPI

  Background:
    Given a new test namespace called 'delete_folder_test_beta'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Deleting a non-existing resource address returns the correct value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address for '<protocol>_delete_folder_non_existing_folder'
    Then calling '<protocol>' DeleteFolder on that address returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 204          |
  
  Scenario Outline: Deleting an existing object with DeleteFolder returns the correct error value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address for '<protocol>_delete_folder_existing_object'
    And an object of size '1024' exists at that address and is readable
    Then calling '<protocol>' DeleteFolder on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | INVALID_ARGUMENT |
      | REST     | 400              |

  Scenario Outline: Deleting an existing empty resource address returns the correct value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1beta' for feature 'filefolder'
    Given a resource address '<protocol>_delete_folder_existent_empty_folder' which is enumerable
    Then calling '<protocol>' DeleteFolder on that address returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 204          |
