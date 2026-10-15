**Cloud object operations now use service-compatible request formatting.**
Azure SAS redirects use whole-second expiry timestamps, Azure Shared Key
conditional and bodyless write requests are signed and framed consistently,
and GCS access checks and zero-byte writes use the service's documented IAM
path and explicit body length. Applications do not need to change their
configuration.
