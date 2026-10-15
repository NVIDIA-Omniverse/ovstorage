Feature: Write()

  Background:
    Given a new test namespace called 'write_test_beta'
    And a connection to the storage service
    And an authenticated user

  Scenario Outline: Direct write of a file performs write
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'small-<protocol>.bin'
    And no object exists at that address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with data returns a created response
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | stat_return_value |
      | GRPC     | OK                |
      | REST     | 204               |

  Scenario Outline: Writing of a medium file returns redirect and the file can be uploaded
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'medium-<protocol>.bin'
    And no object exists at that address
    And a 'medium' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address returns a redirect response
    Then uploading a file following a redirect succeeds
    And calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | stat_return_value |
      | GRPC     | OK                |
      | REST     | 204               |

  Scenario Outline: Completing a redirect upload on a non existing address fails
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'nonexisting-<protocol>.bin'
    And no object exists at that address
    When calling '<protocol>' complete redirect upload returns '<complete_return_value>'
    Examples:
      | protocol | complete_return_value |
      | GRPC     | INVALID_ARGUMENT      |
      | REST     | 400                   |

  Scenario Outline: Writing of a medium file returns redirect, and completing the redirect upload returns the correct resource identity
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'medium-completed-<protocol>.bin'
    And no object exists at that address
    And a 'medium' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address returns a redirect response
    Then uploading a file following a redirect succeeds
    When calling '<protocol>' complete redirect upload returns '<complete_return_value>'
    Examples:
      | protocol | complete_return_value |
      | GRPC     | OK                    |
      | REST     | 200                   |

  Scenario Outline: Writing of a large file returns multipart upload handle
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'large-<protocol>.bin'
    And no object exists at that address
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address returns a multipart upload handle
    Then uploading a file with '<protocol>' in multiple parts returns '<completion_returns>' on completion
    And calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | stat_return_value | completion_returns |
      | GRPC     | OK                | OK                 |
      | REST     | 204               | 200                |

  Scenario Outline: Writing with invalid resource address returns the appropriate status
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And a blob of '2048' bytes
    And an invalid resource address
    Then calling '<protocol>' write on that address returns '<return_value>'
    Examples:
      | protocol | return_value     | size   |
      | GRPC     | INVALID_ARGUMENT | small  |
      | GRPC     | INVALID_ARGUMENT | medium |
      | GRPC     | INVALID_ARGUMENT | large  |
      | REST     | 400              | small  |
      | REST     | 400              | medium |
      | REST     | 400              | large  |

  Scenario Outline: Writing a file without permissions returns the appropriate status
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'no_write_permission-<protocol>.usd'
    And an object of size '1024' exists at that address and is readable
    And user has no permissions to write at that address
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    Then calling '<protocol>' write on that address returns '<return_value>'
    Examples:
      | protocol | return_value      |
      | GRPC     | PERMISSION_DENIED |
      | REST     | 403               |

  @optional
  Scenario Outline: Writing a file without upload preference performs write with the default method
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'medium-with-no-preference-<protocol>.bin'
    And no object exists at that address
    And a 'medium' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'no' upload preference the first roundtrip returns '<write_return_value>'
    Then uploading a file following a redirect succeeds
    And calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | write_return_value | stat_return_value |
      | GRPC     | OK                 | OK                |
      | REST     | 300                | 204               |

  @optional
  Scenario Outline: Writing a file with the body upload preference performs write
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'medium-with-body-preference-<protocol>.bin'
    And no object exists at that address
    And a 'medium' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<write_return_value>'
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | write_return_value | stat_return_value |
      | GRPC     | OK                 | OK                |
      | REST     | 201                | 204               |

  @optional
  Scenario Outline: Writing a file with the redirect upload preference returns redirect
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'large-with-redirect-preference-<protocol>.bin'
    And no object exists at that address
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'redirect' upload preference the first roundtrip returns '<write_return_value>'
    Then uploading a file following a redirect succeeds
    And calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | write_return_value | stat_return_value |
      | GRPC     | OK                 | OK                |
      | REST     | 300                | 204               |

  @optional
  Scenario Outline: Writing a file with the multipart upload preference returns multipart upload handle
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'large-with-multipart-preference-<protocol>.bin'
    And no object exists at that address
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'multipart' upload preference the first roundtrip returns '<write_return_value>'
    Then uploading a file with '<protocol>' in multiple parts returns '<completion_returns>' on completion
    And calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | write_return_value | stat_return_value | completion_returns |
      | GRPC     | OK                 | OK                | OK                 |
      | REST     | 300                | 204               | 200                |

  Scenario Outline: Multipart upload abort succeeds
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'large-abort-<protocol>.bin'
    And no object exists at that address
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'multipart' upload preference the first roundtrip returns '<return_value>'
    Then aborting a multipart upload via '<protocol>' with that id returns '<abort_return_value>'
    And no object exists at that address
    Examples:
      | protocol | return_value | abort_return_value |
      | GRPC     | OK           | OK                 |
      | REST     | 300          | 204                |

  Scenario Outline: Multipart upload abort works also having already completed it - it will do nothing
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'large-abort-fails-<protocol>.bin'
    And no object exists at that address
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'multipart' upload preference the first roundtrip returns '<return_value>'
    Then uploading a file with '<protocol>' in multiple parts returns '<completion_returns>' on completion
    And aborting a multipart upload via '<protocol>' with that id returns '<abort_return_value>'
    And calling '<protocol>' stat on that address returns '<stat_return_value>'
    Examples:
      | protocol | return_value | completion_returns | abort_return_value | stat_return_value |
      | GRPC     | OK           | OK                 | OK                 | OK                |
      | REST     | 300          | 200                | 204                | 204               |

  Scenario Outline: Write is not accepted in case of supplying a non-latest previous_version on Write
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'conflict-write-<protocol>-<upload_method>.bin'
    And an object of size '1024' exists at that address and is readable
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' Stat on that address returns '<first_stat_return_value>'
    And we memorize the last response as 'first_stat'
    And calling '<protocol>' write on that address with 'body' upload preference returns '<first_write_returns>'
    Then calling '<protocol>' write on that address with '<upload_method>' upload preference using the memorized previous version 'first_stat' returns '<second_write_returns>'
    Examples:
        | protocol | first_stat_return_value | first_write_returns | second_write_returns | upload_method |
        | GRPC     | OK                      | OK                  | FAILED_PRECONDITION  | body          |
        | REST     | 204                     | 201                 | 412                  | body          |


  Scenario Outline: Write is accepted in case of supplying the latest previous_version on Write
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'nonconflict-write-<protocol>-<upload_method>.bin'
    And an object of size '1024' exists at that address and is readable
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' Stat on that address returns '<first_stat_return_value>'
    And we memorize the last response as 'first_stat'
    Then calling '<protocol>' write on that address with '<upload_method>' upload preference using the memorized previous version 'first_stat' returns '<write_returns>'
    Examples:
      | protocol | first_stat_return_value | write_returns | upload_method |
      | GRPC     | OK                      | OK            | body          |
      | REST     | 204                     | 201           | body          |

  Scenario Outline: Multipart write is not accepted in case of supplying a non-latest previous_version on CompleteMultipartUpload
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'conflict-multipartwrite-on-complete-<protocol>.bin'
    And an object of size '1024' exists at that address and is readable
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' Stat on that address returns '<first_stat_return_value>'
    And we memorize the last response as 'first_stat'
    And calling '<protocol>' write on that address with 'multipart' upload preference using the memorized previous version 'first_stat' returns '<first_write_returns>'
    And we memorize the last response as 'first_write'
    Given a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' write on that address with 'body' upload preference returns '<second_write_returns>'
    Given a 'large' blob according to the upload options for that address, using '<protocol>'
    Then uploading a file with '<protocol>' in multiple parts using the memorized write response 'first_write' returns '<completion_returns>' on completion
      Examples:
      | protocol | first_stat_return_value | first_write_returns | second_write_returns | completion_returns  |
      | GRPC     | OK                      | OK                  | OK                   | FAILED_PRECONDITION |
      | REST     | 204                     | 300                 | 201                  | 412                 |

  Scenario Outline: Multipart write is accepted in case of supplying the latest previous_version on Write
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'nonconflict-write-<protocol>-on-complete-multipart.bin'
    And an object of size '1024' exists at that address and is readable
    And a 'large' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' Stat on that address returns '<first_stat_return_value>'
    And we memorize the last response as 'first_stat'
    And calling '<protocol>' write on that address with 'multipart' upload preference using the memorized previous version 'first_stat' returns '<write_returns>'
    And we memorize the last response as 'first_write'
    Then uploading a file with '<protocol>' in multiple parts using the memorized write response 'first_write' returns '<completion_returns>' on completion
    Examples:
        | protocol | first_stat_return_value | write_returns | completion_returns |
        | GRPC     | OK                      | OK            | OK                 |
        | REST     | 204                     | 300           | 200                |

    # This test needs revisiting since the original implementation didn't work, and we need to check if the  service can actually do this
  @skip
  Scenario Outline: Redirect upload fails when using a non-latest previous version
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    Given a resource address for 'conflict-redirectwrite-on-complete-<protocol>.bin'
    And an object of size '1024' exists at that address and is readable
    And a 'small' blob according to the upload options for that address, using '<protocol>'
    When calling '<protocol>' Stat on that address returns '<first_stat_return_value>'
    And we memorize the last response as 'first_stat'
    And calling '<protocol>' write on that address with 'body' upload preference returns '<first_write_returns>'
    And calling '<protocol>' write on that address with 'redirect' upload preference returns '<second_write_returns>'
    Then uploading a file following a redirect fails
  Examples:
    | protocol | first_stat_return_value | first_write_returns | second_write_returns |
    | GRPC     | OK                      | OK                  | OK                   |
    | REST     | 204                     | 201                 | 300                  |


  Scenario Outline: Writing a zero-sized file is possible
    Given the service speaks '<protocol>'
    And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
    And a resource address for 'zero-<protocol>.bin'
    And no object exists at that address
    And a blob of zero size
    When performing '<protocol>' write against that address with data succeeds
    Then calling '<protocol>' stat on that address returns '<stat_return_value>'
  Examples:
    | protocol | stat_return_value |
    | GRPC     | OK                |
    | REST     | 204               |
