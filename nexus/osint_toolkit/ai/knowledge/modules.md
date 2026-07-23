# Exact Nexus module catalogue

Use only these internal module names when recommending a Nexus scan.

OSINT modules:

- `email`: email syntax, domain, public account and exposure checks
- `username`: public username presence across supported sites
- `domain`: DNS, WHOIS, certificates and public domain metadata
- `ip`: public IP registration, network and reputation metadata
- `phone`: parsing, country/carrier hints and public lookup links
- `web` or `url`: public page metadata and web-source inspection
- `social`: social-network lookup links for a username or name
- `breach`: public breach-presence checks; never expose passwords
- `github`: public GitHub profile and repository metadata
- `discord`: explicit Discord username availability check
- `image`: reverse-image-search links and image metadata
- `crypto`: public cryptocurrency-address information

Pentest modules:

- `ports`: bounded TCP port discovery
- `subdomains`: subdomain enumeration
- `fingerprint`: exposed web technologies
- `ssl`: TLS and certificate audit
- `dirs`: bounded directory discovery
- `cors`: CORS policy checks
- `open-redirect`: open-redirect detection
- `spring`: exposed Spring Actuator endpoints
- `js`: JavaScript inventory and published-secret patterns
- `s3`: public cloud-bucket exposure checks
- `headers`: HTTP security headers, including CSP
- `dns-sec`: DNSSEC, SPF, DKIM and DMARC checks
- `graphql`: GraphQL endpoint and introspection checks

Names such as `security_headers`, `web_security`, `whois`, `csp` and
`vulnerability_scan` are not internal Nexus module names. WHOIS is part of
`domain`; CSP is checked by `headers`.
