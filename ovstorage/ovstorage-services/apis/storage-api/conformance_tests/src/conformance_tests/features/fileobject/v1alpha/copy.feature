Feature: Copy()

  Background:
    Given a new test namespace called 'copy_test'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Copy of an available data object succeeds
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'source-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    Given a resource address for 'destination-<protocol>.usd'
    And memorizing that resource address as 'destination_address' 
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '1024'

    Examples:
      | protocol | copy_return_value |
      | GRPC     | OK                |
      | REST     | 201               |
  
  Scenario Outline: Copy of an available data object into an invalid destination address fails
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'source-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    Given an invalid resource address
    And memorizing that resource address as 'destination_address'
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value>'

    Examples:
      | protocol | copy_return_value |
      | GRPC     | INVALID_ARGUMENT |
      | REST     | 400               |
  
  Scenario Outline: Copy existing file to folder location
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'source-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    Given a resource address '<protocol>_folder' which is enumerable
    And memorizing that resource address as 'destination_address'
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '1024'

    Examples:
      | protocol | copy_return_value |
      | GRPC     | OK                |
      | REST     | 201               |


  Scenario Outline: Copy of versioned data object succeeds
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'versioning' API in version 'v1alpha' for feature 'versioning'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'source-version-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And we add a version of size '2048' with rand seed '42' at that address
    And we add a version of size '512' with rand seed '123' at that address
    When calling '<protocol>' EnumerateVersions exhaustively on that address returns '<enumerate_return_value>'
    And the EnumerateVersions returned '3' items
    When memorizing the resource address with index '-1' from EnumerateVersions as 'newest_version_address'
    And memorizing the resource address with index '0' from EnumerateVersions as 'oldest_version_address'

    
    # Copy from oldest version first
    Given determining head resource identity with '<protocol>' on memorized address 'oldest_version_address'
    And memorizing that resource identity as 'old_source_identity'
    Given a resource address for 'destination-oldest-<protocol>.usd'
    And memorizing that resource address as 'old_destination_address'
    When calling '<protocol>' copy from memorized 'old_source_identity' to memorized 'old_destination_address' returns '<copy_return_value>'
    And calling '<protocol>' ReadFromAddress on memorized 'old_destination_address'
    Then the '<protocol>' result's resource info has size '1024'
    
    # Copy from newest version second
    Given determining head resource identity with '<protocol>' on memorized address 'newest_version_address'
    And memorizing that resource identity as 'new_source_identity'
    Given a resource address for 'destination-newest-<protocol>.usd'
    And memorizing that resource address as 'new_destination_address'
    When calling '<protocol>' copy from memorized 'new_source_identity' to memorized 'new_destination_address' returns '<copy_return_value>'
    And calling '<protocol>' ReadFromAddress on memorized 'new_destination_address'
    Then the '<protocol>' result's resource info has size '512'
  
  Examples:
    | protocol | enumerate_return_value | copy_return_value |
    | GRPC     | OK                     | OK                |
    | REST     | 200                    | 201               |


  Scenario Outline: Copy  file onto itself
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'source-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    And memorizing that resource address as 'destination_address' 
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '1024'
    
    Examples:
      | protocol | copy_return_value |
      | GRPC     | OK                |
      | REST     | 201               |


  Scenario Outline: Copy overwrites existing destination object
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    Given a resource address for 'source1-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    Given a resource address for 'destination-<protocol>.usd'
    And memorizing that resource address as 'destination_address'
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value1>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '1024'
    Given a resource address for 'source2-<protocol>.usd'
    And an object of size '512' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value2>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '512'
    Examples:
      | protocol | copy_return_value1 | copy_return_value2 |
      | GRPC     | OK                 | OK                 |
      | REST     | 201                | 201                |

  Scenario Outline: Copy can overwrite existing destination object when specifying the correct previous_version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'copy'
    Given a resource address for 'overwrite-source1-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    Given a resource address for 'overwrite-destination-<protocol>.usd'
    And memorizing that resource address as 'destination_address'
    When calling '<protocol>' copy from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value1>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '1024'
    Given a resource address for 'source2-<protocol>.usd'
    And an object of size '512' exists at that address and is readable
    And determining head resource identity with '<protocol>' on memorized address 'destination_address'
    And memorizing that resource identity as 'destination_identity'
    When calling '<protocol>' copy with 'destination_identity' from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value2>'
    Examples:
      | protocol | copy_return_value1 | copy_return_value2  |
      | GRPC     | OK                 | OK                  |
      | REST     | 201                | 201                 |

  Scenario Outline: Copy fails to overwrite existing destination object when specifying the wrong previous_version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'copy'
    Given a resource address for 'overwrite-fails-source1-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity_1024'
    Given a resource address for 'overwrite-fails-destination-<protocol>.usd'
    And memorizing that resource address as 'destination_address'
    When calling '<protocol>' copy from memorized 'source_identity_1024' to memorized 'destination_address' returns '<copy_return_value_success>'
    And calling '<protocol>' ReadFromAddress on memorized 'destination_address'
    Then the '<protocol>' result's resource info has size '1024'

    Given a resource address for 'source2-<protocol>.usd'
    And an object of size '512' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity_512'
    And determining head resource identity with '<protocol>' on memorized address 'destination_address'
    And memorizing that resource identity as 'destination_identity'
    When calling '<protocol>' copy from memorized 'source_identity_512' to memorized 'destination_address' returns '<copy_return_value_success>'
    And calling '<protocol>' copy with 'destination_identity' from memorized 'source_identity_1024' to memorized 'destination_address' returns '<copy_return_value_failed>'
    Examples:
      | protocol | copy_return_value_success | copy_return_value_failed  |
      | GRPC     | OK                        | FAILED_PRECONDITION       |
      | REST     | 201                       | 412                       |

  Scenario Outline: Copy to non-existing destination with unrelated previous_version for source should fail
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
    And the '<protocol>' service supports optimistic locking for 'copy'
    And a resource address for 'conditional-copy-src4-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And determining head resource identity with '<protocol>'
    And memorizing that resource identity as 'source_identity'
    And a resource address for 'conditional-copy-dst-nonexist-<protocol>.usd'
    And no object exists at that address
    And memorizing that resource address as 'destination_address'
    And determining another object's resource identity with '<protocol>'
    And memorizing that resource identity as 'unrelated_version'
    When calling '<protocol>' copy with 'unrelated_version' from memorized 'source_identity' to memorized 'destination_address' returns '<copy_return_value>'
    Examples:
      | protocol | copy_return_value   |
      | GRPC     | FAILED_PRECONDITION |
      | REST     | 412                 |
