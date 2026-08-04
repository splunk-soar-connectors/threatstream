**Unreleased**
* Tag observable now applies the documented TLP red default when callers omit the TLP parameter.
* Reputation and WHOIS actions now encode indicator values before placing them in API path segments.
* Incident and rule retrieval now return action errors cleanly when identifier validation fails.
* Import-session and observable updates now reject malformed or past expiration timestamps before sending requests.
* Import-session update now reports an action error when any requested sub-operation fails.
* Form-backed import and detonation actions now serialize structured field values before request encoding.
* Scheduled polling now prevents malformed or future incident timestamps from advancing its saved checkpoint.
* Polling now skips isolated incident-detail failures without advancing the retry checkpoint past them.
* Scheduled polling now consumes first-run state only after the bounded initial run completes successfully.
* The get-observable widget now escapes the intelligence identifier before embedding it in JavaScript.
