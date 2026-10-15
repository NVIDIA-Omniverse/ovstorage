Feature: CreateFolder(), FileFolderAPI v1alpha

  Background:
    Given a new test namespace called 'create_folder_test_v1alpha'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Creating a new empty folder returns the correct value, the folder can be listed and deleted again
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'not as' 'no_empty'
    Given a resource address '<protocol>_create_folder_new_folder' which is enumerable
    And no object exists at that address
    When calling '<protocol>' List exhaustively on that address returns '<invalid_list_return_value>'
    And calling '<protocol>' CreateFolder on that address returns '<return_value>'
    Then calling '<protocol>' List exhaustively on that address returns '<list_return_value>'
    And the number of returned list entries is '0'
    And calling '<protocol>' DeleteFolder on that address returns '<delete_return_value>'
    And calling '<protocol>' List exhaustively on that address returns '<invalid_list_return_value>'
    Examples:
      | protocol | invalid_list_return_value | return_value | list_return_value | delete_return_value |
      | GRPC     | NOT_FOUND                 | OK           | OK                | OK                  |
      | REST     | 404                       | 204          | 200               | 204                 |

  Scenario Outline: A folder which is created by CreateFolder can not be found by a Stat command
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'not as' 'no_empty'
    Given a resource address '<protocol>_created_folder_cant_be_read' which is enumerable
    And no object exists at that address
    When calling '<protocol>' CreateFolder on that address returns '<create_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | create_return_value | stat_return_value     |
      | GRPC     | OK                  | NOT_FOUND             |
      | REST     | 204                 | 404                   |

  Scenario Outline: A folder which is created by CreateFolder can not be used for a ReadFromAddress command and reports as invalid argument in native folder mode
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'native'
    Given a resource address for '<protocol>_created_folder_cant_be_read_in_native_mode'
    And no object exists at that address
    When calling '<protocol>' CreateFolder on that address returns '<create_return_value>'
    Then calling '<protocol>' ReadFromAddress on that address the service returns '<read_return_value>'
    Examples:
      | protocol | create_return_value | read_return_value     |
      | GRPC     | OK                  | INVALID_ARGUMENT      |
      | REST     | 204                 | 400                   |

  Scenario Outline: A folder which is created by CreateFolder can not be used for a ReadFromAddress command and reports not found in hybrid folder mode
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'hybrid'
    Given a resource address for '<protocol>_created_folder_cant_be_read_in_hybrid_mode'
    And no object exists at that address
    When calling '<protocol>' CreateFolder on that address returns '<create_return_value>'
    Then calling '<protocol>' ReadFromAddress on that address the service returns '<read_return_value>'
    Examples:
      | protocol | create_return_value | read_return_value     |
      | GRPC     | OK                  | NOT_FOUND             |
      | REST     | 204                 | 404                   |

  Scenario Outline: Enumerate of an empty folder created by CreateFolder without content works
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'not as' 'no_empty'
    Given a resource address 'empty-enumerate-<protocol>' which is enumerable
    When calling '<protocol>' CreateFolder on that address returns '<create_folder_return_value>'
    Then calling '<protocol>' Enumerate exhaustively on that address returns '<enumerate_return_value>'
    And the number of returned enumerate entries is '0'
    Examples:
      | protocol | create_folder_return_value | enumerate_return_value     |
      | GRPC     | OK                         | OK                         |
      | REST     | 204                        | 200                        |

  Scenario Outline: Creating a folder that already exists returns the correct value (idempotent)
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    Given a resource address for '<protocol>_create_folder_existing_folder'
    And a folder exists at that address
    Then calling '<protocol>' CreateFolder on that address returns '<return_value>'
    Examples:
      | protocol | return_value |
      | GRPC     | OK           |
      | REST     | 204          |

  Scenario Outline: Creating a folder with an invalid resource address returns the correct error value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    Given an invalid resource address
    Then calling '<protocol>' CreateFolder on that address returns '<return_value>'
    Examples:
      | protocol | return_value     |
      | GRPC     | INVALID_ARGUMENT |
      | REST     | 400              |

  Scenario Outline: Creating a folder where a file already exists returns the correct error value
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    Given a resource address for '<protocol>_create_folder_file_conflict'
    And an object of size '1024' exists at that address and is readable
    Then calling '<protocol>' CreateFolder on that address returns '<return_value>'
    Examples:
      | protocol | return_value        |
      | GRPC     | FAILED_PRECONDITION |
      | REST     | 409                 |

  Scenario Outline: Folders are always created as a side-effect of an upload and can be enumerated and listed
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    Given a resource address '<protocol>_test_folder_as_side_effect' which is enumerable
    And memorizing that resource address as 'folder_address'
    And a new object address 'uploaded_blob.usd.0' within the given address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<write_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<list_return_value>'
    And the number of returned list entries is '1'
    Then calling '<protocol>' Enumerate exhaustively on the address 'folder_address' returns '<enumerate_return_value>'
    And the number of returned enumerate entries is '1'
    Examples:
      | protocol | write_return_value | list_return_value | enumerate_return_value |
      | GRPC     | OK                 | OK                | OK                     |
      | REST     | 201                | 200               | 200                    |

  Scenario Outline: On systems without empty folders, folders are always created as a side-effect of an upload and vanish when the file is removed again
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'no_empty'
    Given a resource address '<protocol>_test_folder_as_side_effect' which is enumerable
    And memorizing that resource address as 'folder_address'
    And a new object address 'uploaded_blob.usd.0' within the given address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<write_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<list_return_value>'
    And the number of returned list entries is '1'
    When calling '<protocol>' delete on that address returns '<delete_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<second_list_return_value>'
    Examples:
      | protocol | write_return_value | list_return_value | delete_return_value | second_list_return_value |
      | GRPC     | OK                 | OK                | OK                  | NOT_FOUND                |
      | REST     | 201                | 200               | 204                 | 404                      |

  Scenario Outline: On a system with native folders, folders are created as a side-effect of an upload and stay even if the uploaded file is deleted
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'native'
    Given a resource address 'test_list_after_delete_<protocol>' which is enumerable
    And memorizing that resource address as 'folder_address'
    And a new object address 'uploaded_blob.usd.0' within the given address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<write_return_value>'
    When calling '<protocol>' delete on that address returns '<delete_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<list_return_value>'
    Examples:
      | protocol | write_return_value | delete_return_value | list_return_value |
      | GRPC     | OK                 | OK                  | OK                |
      | REST     | 201                | 204                 | 200               |

  Scenario Outline: On a system without native folders, folders are created as a side-effect of an upload and vanish if the uploaded file is deleted
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'not as' 'native'
    Given a resource address '<protocol>_test_list_after_delete_no_native' which is enumerable
    And memorizing that resource address as 'folder_address'
    And a new object address 'uploaded_blob-<protocol>.usd.0' within the given address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<write_return_value>'
    When calling '<protocol>' delete on that address returns '<delete_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<list_return_value>'
    Examples:
      | protocol | write_return_value | delete_return_value | list_return_value |
      | GRPC     | OK                 | OK                  | NOT_FOUND         |
      | REST     | 201                | 204                 | 404               |

  Scenario Outline: Folders which are created as a side-effect of an upload can not be deleted because they are not empty in non-hybrid mode
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'not as' 'hybrid'
    Given a resource address '<protocol>_test_delete_non_empty' which is enumerable
    And memorizing that resource address as 'folder_address'
    And an object of size '64' within that address which is named 'Uploaded-<protocol>.usd'
    Then calling '<protocol>' DeleteFolder on the address 'folder_address' returns '<delete_return_value>'
    Examples:
      | protocol | delete_return_value |
      | GRPC     | FAILED_PRECONDITION |
      | REST     | 400                 |

  Scenario Outline: Folders can be created explicitly and stay around even if a file is uploaded into it and removed again
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'not as' 'no_empty'
    Given a resource address '<protocol>_test_list_after_create_and_delete' which is enumerable
    And memorizing that resource address as 'folder_address'
    When calling '<protocol>' CreateFolder on that address returns '<create_return_value>'
    Given an object of size '64' within that address which is named 'Uploaded-<protocol>.usd'
    When calling '<protocol>' delete with memorized 'Uploaded-<protocol>.usd' returns '<delete_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<list_return_value>'
    Examples:
      | protocol | create_return_value | delete_return_value | list_return_value |
      | GRPC     | OK                  | OK                  | OK                |
      | REST     | 204                 | 204                 | 200               |

  Scenario Outline: On a system with hybrid folder mode, folders which were created as a side-effect of an upload can be made explicit and stay around even after the file has been deleted
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'hybrid'
    Given a resource address '<protocol>_test_list_after_delete_no_native' which is enumerable
    And memorizing that resource address as 'folder_address'
    And a new object address 'uploaded_blob-<protocol>.usd.0' within the given address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<write_return_value>'
    And calling '<protocol>' CreateFolder on the address 'folder_address' returns '<create_folder_return_value>'
    When calling '<protocol>' delete on that address returns '<delete_return_value>'
    Then calling '<protocol>' List on the memorized address 'folder_address' returns '<list_return_value>'
    And the number of returned list entries is '0'
    Examples:
      | protocol | write_return_value | create_folder_return_value | delete_return_value | list_return_value |
      | GRPC     | OK                 | OK                         | OK                  | OK                |
      | REST     | 201                | 204                        | 204                 | 200               |
