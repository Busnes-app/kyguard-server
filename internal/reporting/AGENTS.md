# Reporting

## Purpose
The traffic-light scorecard (spec §8.1–§8.3): one authorized dataset, one classifier, one
filter and one CSV writer, shared by the dashboard and the JSON and CSV exports.

## Ownership
Owns `Build` (the dataset), `Classify` (class and health overlay), `Filter`, `Summarize`
and `WriteCSV`. The store owns the facts it reads (`Inventory().ReportFacts`); the API owns
the routes and the export audit.

## Local Contracts
- Class order is fixed: Green needs a schedule in the current verified policy and at least
  one `release` receipt; else Yellow needs a current envelope; else Red. Health never
  changes the class. Decommissioned accounts are counted (by the same pool and attribute filters; a class
  or health filter excludes them), never classified.
- Health is one value: a non-`healthy` broker report first, then `checkout_open`, then
  `pending_first_rotation` (scheduled, never released), then `overdue` (the newest
  occurrence due at least one interval ago came after the last release), else `healthy`.
- Visibility: admins see every account. Anyone else sees accounts they own, or whose
  current policy lists a principal whose verified `KeyEnrollmentManifest` names the
  caller's own non-empty issuer and subject (`sameIdentity`). A subject alone never
  matches. The API passes `""` as the issuer whenever it cannot name it.
- Percentages are whole numbers by largest remainder, so they always sum to 100.
- CSV cells that start with `= + - @`, tab or CR are prefixed with `'`.

## Verification
- `go test ./internal/reporting/` (classifier, percentages, filter, CSV);
  `go test ./internal/api/ -run Scorecard` (acceptance 12 end to end).

## Child DOX Index
None.
