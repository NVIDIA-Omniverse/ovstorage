Feature: ListTopLevelAddresses() CapabilitesAPI

  Background:
    Given a connection to the storage service
    And an authenticated user

Scenario Outline: Top-level addresses are discoverable and enumerable
  Given the service speaks '<protocol>'
  And the '<protocol>' service supports the 'capabilities' API in version 'v1beta' for feature 'capabilities'
  And the '<protocol>' service supports the 'fileobject' API in version 'v1beta' for feature 'fileobject'
  When calling '<protocol>' ListTopLevelAddresses returns '<return_value>'
  When we memorize the last response as 'top_level_addresses'
  Then calling '<protocol>' Enumerate on that topleveladdresses returns '<return_value>'
Examples:
  | protocol | return_value |
  | GRPC     | OK           |
  | REST     | 200          |