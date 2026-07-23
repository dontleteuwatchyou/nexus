# Web security assessment

Begin with fingerprint, headers, TLS, DNS security and JavaScript inventory.
Active discovery such as directory enumeration, port scans, fuzzing or
vulnerability templates must stay inside the agreed scope.

A missing security header is a defence gap, not proof of exploitation. Confirm
findings manually, preserve the request and response evidence, estimate impact
and likelihood separately, and include a concrete remediation. Use OWASP Juice
Shop, WebGoat, DVWA or another isolated lab for exploit training examples.

Never invent a CVE from a product banner. Version matches are hypotheses until
the affected configuration and vendor advisory are verified.
