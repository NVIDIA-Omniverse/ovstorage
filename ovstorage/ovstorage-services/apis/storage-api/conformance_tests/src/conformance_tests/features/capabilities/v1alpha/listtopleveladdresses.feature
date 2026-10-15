Feature: ListTopLevelAddresses() CapabilitiesAPI

  Background:
    Given a connection to the storage service
    And an authenticated user

Scenario Outline: Top-level addresses are discoverable and enumerable
  Given the service speaks '<protocol>'
  And the '<protocol>' service supports the 'capabilities' API in version 'v1alpha' for feature 'capabilities'
  And the '<protocol>' service supports the 'fileobject' API in version 'v1alpha' for feature 'fileobject'
  When calling '<protocol>' ListTopLevelAddresses returns '<return_value>'
  Then calling '<protocol>' Enumerate on that topleveladdresses returns '<return_value>'
Examples:
  | protocol | return_value |
  | GRPC     | OK           |
  | REST     | 200          |