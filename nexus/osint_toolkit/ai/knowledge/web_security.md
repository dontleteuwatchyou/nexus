# Web security assessment

Dans Nexus, l'absence de Content-Security-Policy se vérifie avec le module
exact `headers`. Il n'existe pas de module `security_headers` ni de module
`web_security`. Une CSP absente est un manque de défense, pas une vulnérabilité
exploitée ou une sévérité automatiquement critique.

Begin with fingerprint, headers, TLS, DNS security and JavaScript inventory.
Active discovery such as directory enumeration, port scans, fuzzing or
vulnerability templates must stay inside the agreed scope.

A missing security header is a defence gap, not proof of exploitation. Confirm
findings manually, preserve the request and response evidence, estimate impact
and likelihood separately, and include a concrete remediation. Use OWASP Juice
Shop, WebGoat, DVWA or another isolated lab for exploit training examples.

Never invent a CVE from a product banner. Version matches are hypotheses until
the affected configuration and vendor advisory are verified.
