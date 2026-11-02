# Governance

## Current model: single maintainer (BDFL-style, temporary)

DPG is started by one maintainer (the project founder). Until there are at least two active
maintainers, the founder has final say on scope, architecture and releases.

## Roles

| Role | Can do | How to become one |
|---|---|---|
| Contributor | Open issues and PRs | Anyone |
| Reviewer | Approve PRs in an area | Sustained quality contributions; nominated by a maintainer |
| Maintainer | Merge, release, triage security reports | Nominated by maintainers, no objection within 7 days |

## Decisions

- Day-to-day changes: one maintainer approval.
- Security-sensitive code (`dpg-restore`, `dpg-protect` store, `dpg-connect` proxy auth, fail-closed paths): maintainer approval **and** passing security test suite; a second reviewer once one exists.
- Architecture, scope, licence, dependency policy: proposed in an issue, open for comment for at least 7 days.

## Open-source commitment

The detection, policy, masking, mapping and restoration engine is and stays open source under
Apache-2.0. Any commercial offering is built around the project (for example support, hosted
policy sync, signed builds). 

## Contact

Maintainer contact: to be published (pending).
