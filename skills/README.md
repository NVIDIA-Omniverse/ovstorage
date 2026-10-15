# Skills

These routes apply to the assembled public checkout. Shared skills describe
user/operator workflows and state their working directory in their
`compatibility` metadata. Component skills use paths relative to their own
component unless their instructions say otherwise. Run storage component commands
from `ovstorage/` and resolver component commands from `ovstorage-usd-resolver/`.

Use these guides to select the workflow for your task:

- [ovstorage expert](ovstorage-expert/SKILL.md): start here for using,
  building, configuring, or validating ovstorage and the USD
  resolver, embedding the resolver, or changing its OpenUSD SDK. It routes to
  the component skills below.
- [Storage skill inventory](../ovstorage/AGENTS.md#invocable-skills): linked runtime, operator
  and contributor skills. Broker operator routes apply to existing deployments.
- [Resolver agent guide](../ovstorage-usd-resolver/AGENTS.md): USD resolution,
  embedding, and integration verification.

The [getting-started guide](../docs/getting-started.md) explains component
working directories, and the [combined build guide](../docs/building.md) covers
building both components together. Storage skills are `SKILL.md`
packages; resolver `.agents` pages are component workflow guides. Do not
register every nested service/reference skill as a storage library workflow.
The [root agent entry](../AGENTS.md) routes work across the two components.
