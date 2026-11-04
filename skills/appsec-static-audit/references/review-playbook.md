# Manual review playbook

Use after the scan. For each domain: what to read, the questions to answer, and what evidence supports `PASS`. Adapt to the stack; mark inapplicable items `N/A` with a reason.

Start with: entry points (routes, controllers, GraphQL resolvers, queue consumers, scheduled jobs), the authentication/authorization layer, models and schemas holding SSN/financial/tax data, config and deployment files.

## 4.1 OWASP Top 10 in code
Trace each untrusted source (query, body, headers, cookies, uploaded files, messages, DB content rendered later) to each sink (SQL/NoSQL, shell, template/HTML, file system, outbound HTTP, deserializer, XML parser, redirect).
- Is every query parameterized, including ORM raw/native calls and dynamic ORDER BY / column names?
- Do outbound fetches (webhooks, importers, PDF/image renderers) restrict scheme, host, and private ranges (169.254.169.254, RFC1918)?
- Are paths canonicalized and confined (`realpath` startswith base)? Are uploads allowlisted by content, size-limited, renamed, stored outside the web root and served with safe headers?
- Is native deserialization (pickle, Java serialization, .NET BinaryFormatter, YAML load) ever fed external data, including cache/session/queue contents?

## 4.2 Access control
List every route/resolver/job and its policy. Walk each object-by-ID read/update/delete.
- Default deny, or opt-in protection? Any route missing a check?
- Does each object access filter by owner/tenant/role (taxpayer, case, filing, document, export)? Test mentally with another user's ID.
- Can a request set `role`, `isAdmin`, `status`, `owner_id` (mass assignment, hidden form fields, JWT claims the client controls)?
- Are staff/admin functions separated; is there a break-glass path; who can read FTI and is that logged?

## 4.3 SSO and identity
Read the whole login/callback/logout path and the IdP configuration.
- SAML: signature validated on assertion or response against pinned IdP cert; XML signature wrapping defences; Audience == SP entityID; Recipient/Destination == ACS URL; NotOnOrAfter and clock skew; InResponseTo bound to a stored request ID; consumed assertion IDs cached; unsolicited responses policy.
- OIDC: `state` random, stored, compared; `nonce` in ID token verified; PKCE S256; exact-match redirect URIs; `iss`, `aud`, `exp`, `nbf` validated; JWKS fetched from the configured issuer only; token endpoint auth.
- JWT: algorithm allowlist (reject `none`, no RS/HS confusion), key source, expiry, audience; no decode-without-verify driving decisions.
- Roles: IdP group/claim -> app role through an explicit server-side map; unknown group -> least privilege.
- Bypass: local login routes, seeded admin accounts, `/debug`, feature flags, env switches, test tokens, default credentials, "remember me" or API keys that skip SSO.

## 4.4 Session management
- Cookie flags (Secure, HttpOnly, SameSite) at every `Set-Cookie`/framework setting; cookie prefix use.
- Idle and absolute timeouts server-side; re-authentication for sensitive actions.
- New session ID at login and privilege change; invalidation at logout; SAML SLO / OIDC logout; refresh token revocation.
- Tokens not in localStorage; no session IDs in URLs or logs.

## 4.5 MFA
- Where is MFA enforced (IdP policy, app step-up, `amr`/`acr` claim check)? Is it mandatory for staff and admin paths and for access to FTI?
- Can it be skipped by parameter, config, "trusted device", API route, or recovery flow? Are enrolment and reset flows resistant to takeover?
- If enforcement lives only in the IdP, mark `NOT VERIFIED` and say which policy must be confirmed.

## 4.6 Secrets
- Review each scanner hit; classify live vs test/placeholder by format, location and usage. Check CI files, compose, Helm values, Terraform variables/tfvars/state, notebooks, docs.
- Git history: for each hit decide rotate + purge. Anything exposed once is compromised.
- Confirm runtime loading from a secrets manager/KMS, and that images/layers do not embed secrets.

## 4.7 Dependencies and SBOM
- Direct and transitive runtime dependencies with known CVEs; EOL runtimes/frameworks; abandoned packages; unpinned or VCS/URL dependencies; missing lockfiles; install scripts; private-registry/dependency-confusion exposure (internal package names resolvable publicly).
- State that CVE coverage offline is partial; list what must be re-scanned online.

## 4.8 Cryptography
- Password storage (Argon2id/bcrypt/scrypt/PBKDF2, salt, cost); integrity hashes; ciphers and modes (AES-GCM); IV/nonce uniqueness; key length, storage, rotation, separation from data; CSPRNG for tokens/OTP/reset codes.
- TLS: versions, ciphers, certificate validation, HSTS, internal service TLS. For FTI: FIPS 140-validated modules, TLS 1.2+ with approved suites.
- Homegrown crypto, custom token formats, encoding mistaken for encryption.

## 4.9 Data protection (PII / FTI)
- Inventory fields: SSN/TIN, bank/routing numbers, income, tax return data, DOB, address. Where stored, how encrypted (field-level / TDE / none), who can read, how masked in UI/API/exports.
- Leakage: logs, error messages, URLs, analytics, caches, temp files, backups, test fixtures, support tooling.
- Retention and disposal: automated purge, soft-delete vs real delete, backup lifecycle, audit of disposal (Pub 1075 disposal rules for FTI).
- FTI segregation and labelling; no FTI in non-production environments.

## 4.10 API security
- Authentication on every endpoint (global middleware vs per-route); service-to-service auth; API keys scoping.
- Input validation schemas (type, length, range, format); output DTOs (no over-exposure); mass assignment protection.
- Rate limiting on login, MFA, reset, search, export; pagination limits; request size limits; GraphQL depth/cost limits and introspection off in production.
- Verb tampering, CORS, CSRF for cookie-authenticated APIs.

## 4.11 Infrastructure as code and config
- Terraform/CloudFormation/ARM/Pulumi: public buckets, 0.0.0.0/0 ingress, public DBs, wildcard IAM, missing encryption at rest/in transit, key rotation, logging disabled, default VPC, instance metadata v2, secrets in state/variables.
- Kubernetes: privileged/root, capabilities, hostPath/hostNetwork, service account tokens, RBAC (cluster-admin), network policies, secrets as plain env, mutable image tags, resource limits, Pod Security level.
- Docker: pinned base digest, non-root USER, no secrets in layers, minimal image, no `curl | sh`.
- App/server config: debug flags, CORS, CSP/HSTS/X-Frame-Options/nosniff/Referrer-Policy, directory listing, admin consoles, actuator endpoints, default accounts.

## 4.12 Logging and audit trails
- Events logged: login success/failure, MFA, logout, authorization failures, role changes, admin actions, FTI/PII read and export, config changes, errors in security paths. Fields: who, what, when, where (IP), outcome, record ID.
- Protection: central shipping, tamper resistance, access control, retention to policy; time sync.
- No SSN, passwords, tokens, full request bodies in logs; log-injection safe; failures in logging do not silently disable auditing.

## 4.13 Error handling
- Global handler returns generic message + correlation ID; no stack traces, SQL, file paths, versions or internal hostnames to users; debug pages disabled in production profiles; security checks fail closed; 404/403 do not reveal object existence where that matters.

## Severity guidance (calibrate with context)
- Critical: unauthenticated RCE/SQLi, auth bypass, live production secrets, public bucket with PII/FTI, SAML signature not validated.
- High: authenticated injection, IDOR on SSN/tax records, missing encryption of FTI, JWT validation gaps, privileged containers on public workloads, MFA absent for admins.
- Medium: missing rate limiting on sensitive routes, weak session settings, verbose errors, missing security headers, unpinned dependencies.
- Low/Info: hardening, hygiene, observations.
Adjust up for FTI/SSN exposure and internet reachability; adjust down for unreachable code, test-only code, or demonstrated compensating controls.
