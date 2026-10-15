# Notifications API

This folder groups the two Notifications API release snapshots:

| API | Local path | Contents |
|---|---|---|
| Aggregation / Publisher | [`aggregation/`](aggregation/) | `EventPublishingService`, proto, OpenAPI, generated docs, changelog, license |
| Consumer | [`consumer/`](consumer/) | `EventConsumerService`, proto, OpenAPI, generated docs, changelog, license |

Keep the two snapshots separate. They are related API families, but they ship as
independent release bundles with their own changelogs and license files.

See [`../README.md`](../README.md) for the overall service API map.
