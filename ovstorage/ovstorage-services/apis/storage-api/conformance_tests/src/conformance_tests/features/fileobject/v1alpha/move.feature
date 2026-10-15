Feature: Move()

  Background:
    Given a new test namespace called 'move_test'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Move an existing file to a new folder location
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'source-file-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address '<protocol>_folder' which is enumerable
    And memorizing that resource address as 'destination_folder'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_folder' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | OK                |
      | REST     | 201               |

  Scenario Outline: Move an existing file from an invalid source identity should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'move'
    And a resource address for 'source-file-with-invalid-identity-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And an invalid resource identity
    And memorizing the last resource identity as 'invalid_identity'
    And a resource address '<protocol>_dest_folder' which is enumerable
    And memorizing that resource address as 'destination_folder'
    Then calling '<protocol>' move with source identity from address 'source_file' and identity 'invalid_identity' to address 'destination_folder' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |

  Scenario Outline: Move a file with invalid destination resource address should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'source-file-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And an invalid resource address
    And memorizing that resource address as 'destination_folder'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_folder' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |
    
  Scenario Outline: Rename a file within the same parent folder
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'original-name-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address for 'new-name-<protocol>.txt'
    And no object exists at that address
    And memorizing that resource address as 'destination_file'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_file' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | OK                |
      | REST     | 201               |


  Scenario Outline: Move operation preserves data integrity
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'data-integrity-source-<protocol>.txt'
    And a test object of size '512' with rand seed '123456' at that address
    And memorizing that resource address as 'source_file'
    And a resource address for 'data-integrity-dest-<protocol>.txt'
    And memorizing that resource address as 'destination_file'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_file' returns '<move_return_value>'
    When calling '<protocol>' ReadFromAddress on memorized 'destination_file'
    Then the '<protocol>' call should return '<read_return_value>'
    And the '<protocol>' result's resource info has size '512'
    And calling '<protocol>' ReadFromAddress with mode 'body' on memorized 'destination_file' downloads the data using the specified preference and it has the correct content for rand seed '123456'
    Examples:
      | protocol | move_return_value | read_return_value |
      | GRPC     | OK                | OK                |
      | REST     | 201               | 200               |


  Scenario Outline: Move existing file to existing file location
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'src-exists-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address for 'dst-exists-<protocol>.txt'
    And an object of size '512' exists at that address and is readable
    And memorizing that resource address as 'destination_file'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_file' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | OK                |
      | REST     | 201               |

  Scenario Outline: Move existing file to invalid destination
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'src-exists4-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And an invalid resource address
    And memorizing that resource address as 'invalid_destination'
    Then calling '<protocol>' move from address 'source_file' to address 'invalid_destination' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |

  Scenario Outline: Move non-existing file to existing file location
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'src-missing-<protocol>.txt'
    And no object exists at that address
    And memorizing that resource address as 'source_file'
    And a resource address for 'dst-exists2-<protocol>.txt'
    And an object of size '512' exists at that address and is readable
    And memorizing that resource address as 'destination_file'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_file' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | NOT_FOUND         |
      | REST     | 404               |

  Scenario Outline: Move non-existing file to non-existing location
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'src-missing2-<protocol>.txt'
    And no object exists at that address
    And memorizing that resource address as 'source_file'
    And a resource address for 'dst-missing-<protocol>.txt'
    And no object exists at that address
    And memorizing that resource address as 'destination_file'
    Then calling '<protocol>' move from address 'source_file' to address 'destination_file' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | NOT_FOUND         |
      | REST     | 404               |

  Scenario Outline: Move folder to invalid destination
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And a resource address 'src-folder4-<protocol>' which is enumerable
    And an object of size '1024' within that address which is named 'dummy.txt'
    And memorizing that resource address as 'source_folder'
    And an invalid resource address
    And memorizing that resource address as 'invalid_destination'
    Then calling '<protocol>' move from address 'source_folder' to address 'invalid_destination' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |

  Scenario Outline: Move folder to valid destination fails because folders cannot be moved, in native mode it returns INVALID_ARGUMENT
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'native'
    And a resource address 'src-folder5-<protocol>' which is enumerable
    And an object of size '1024' within that address which is named 'dummy.txt'
    And memorizing that resource address as 'source_folder'
    And a resource address 'dst-folder5-<protocol>' which is enumerable
    And memorizing that resource address as 'valid_destination'
    Then calling '<protocol>' move from address 'source_folder' to address 'valid_destination' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |

  Scenario Outline: Move folder to valid destination fails because folders cannot be moved, in hybrid mode it returns NOT_FOUND
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports the 'filefolder' API in version 'v1alpha' for feature 'filefolder'
    And the '<protocol>' service reports having native folders 'as' 'hybrid'
    And a resource address 'src-folder5-<protocol>' which is enumerable
    And an object of size '1024' within that address which is named 'dummy.txt'
    And memorizing that resource address as 'source_folder'
    And a resource address 'dst-folder5-<protocol>' which is enumerable
    And memorizing that resource address as 'valid_destination'
    Then calling '<protocol>' move from address 'source_folder' to address 'valid_destination' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | NOT_FOUND         |
      | REST     | 404               |

  Scenario Outline: Move file onto itself should be no-op
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And a resource address for 'self-move-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    Then calling '<protocol>' move from address 'source_file' to address 'source_file' returns '<move_return_value>'
    When calling '<protocol>' Stat on memorized 'source_file'
    Then the '<protocol>' call should return '<stat_return_value>'
    And the '<protocol>' result's resource info has size '1024'
    Examples:
      | protocol | move_return_value | stat_return_value |
      | GRPC     | OK                | OK                |
      | REST     | 201               | 204               |

  Scenario Outline: Move from invalid source to invalid destination
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And an invalid resource address
    And memorizing that resource address as 'invalid_source'
    And an invalid resource address
    And memorizing that resource address as 'invalid_destination'
    Then calling '<protocol>' move from address 'invalid_source' to address 'invalid_destination' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | INVALID_ARGUMENT  |
      | REST     | 400               |

  Scenario Outline: Move with valid destination_previous_version should succeed
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'move'
    And a resource address for 'conditional-src-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address for 'conditional-dst-<protocol>.txt'
    And an object of size '512' exists at that address and is readable
    And memorizing that resource address as 'destination_file'
    And determining head resource identity with '<protocol>' on memorized address 'destination_file'
    And memorizing that resource identity as 'destination_previous_version'
    Then calling '<protocol>' move with destination identity from address 'source_file' to address 'destination_file' with identity 'destination_previous_version' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | OK                |
      | REST     | 201               |

  Scenario Outline: Move with outdated destination_previous_version should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'move'
    And a resource address for 'conditional-src-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address for 'conditional-dst-<protocol>.txt'
    And an object of size '512' exists at that address and is readable
    And memorizing that resource address as 'destination_file'
    And determining head resource identity with '<protocol>' on memorized address 'destination_file'
    And memorizing that resource identity as 'old_destination_version'
    And we add a version of size '256' with rand seed '98765' at that address
    Then calling '<protocol>' move with destination identity from address 'source_file' to address 'destination_file' with identity 'old_destination_version' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value   |
      | GRPC     | FAILED_PRECONDITION |
      | REST     | 412                 |

  Scenario Outline: Move to non-existing destination with unrelated destination_previous_version should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'move'
    And a resource address for 'conditional-src-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address for 'conditional-dst-nonexist-<protocol>.txt'
    And no object exists at that address
    And memorizing that resource address as 'destination_file'
    And determining another object's resource identity with '<protocol>'
    And memorizing that resource identity as 'unrelated_version'
    Then calling '<protocol>' move with destination identity from address 'source_file' to address 'destination_file' with identity 'unrelated_version' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value   |
      | GRPC     | FAILED_PRECONDITION |
      | REST     | 412                 |

  Scenario Outline: Move with both source_resource_address and source_resource_identity (optimistic locking for source) should succeed
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'move'
    And a resource address for 'optimistic-src-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    And a resource address for 'optimistic-dst-<protocol>.txt'
    And memorizing that resource address as 'destination_file'
    When calling '<protocol>' Stat on memorized 'source_file'
    And we memorize the last response as 'stat_source'
    Then calling '<protocol>' move with source identity from address 'source_file' and identity 'stat_source' to address 'destination_file' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value |
      | GRPC     | OK                |
      | REST     | 201               |

  Scenario Outline: Move with outdated source_resource_identity should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'move'
    And a resource address for 'optimistic-src-outdated-<protocol>.txt'
    And an object of size '1024' exists at that address and is readable
    And memorizing that resource address as 'source_file'
    When calling '<protocol>' Stat on memorized 'source_file'
    And we memorize the last response as 'old_source_identity'
    And we add a version of size '512' with rand seed '54321' at that address
    Given a resource address for 'optimistic-dst-outdated-<protocol>.txt'
    And memorizing that resource address as 'destination_file'
    Then calling '<protocol>' move with source identity from address 'source_file' and identity 'old_source_identity' to address 'destination_file' returns '<move_return_value>'
    Examples:
      | protocol | move_return_value   |
      | GRPC     | FAILED_PRECONDITION |
      | REST     | 412                 |