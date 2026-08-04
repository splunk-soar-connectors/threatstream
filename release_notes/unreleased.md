**Unreleased**
* Tag observable now applies the documented TLP red default when callers omit the TLP parameter.
* Reputation and WHOIS actions now encode indicator values before placing them in API path segments.
* Incident and rule retrieval now return action errors cleanly when identifier validation fails.
* Import-session and observable updates now reject malformed or past expiration timestamps before sending requests.
