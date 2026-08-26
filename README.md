# Java Vulnerability Lab

This is an intentionally vulnerable Spring Boot application for testing CodeQL,
code-review agents, and other static-analysis tools. It must only be run locally in
an isolated test environment. Never deploy it or expose port 8080 to a network.

## Included vulnerabilities

| Endpoint / location | Deliberate weakness | CWE |
| --- | --- | --- |
| `GET /api/users?name=` | SQL injection | CWE-89 |
| `GET /api/run?command=` | OS command injection | CWE-78 |
| `GET /api/files?name=` | Path traversal | CWE-22 |
| `GET /api/greeting?name=` | Reflected cross-site scripting | CWE-79 |
| `GET /api/fetch?url=` | Server-side request forgery | CWE-918 |
| `GET /api/redirect?url=` | Unvalidated redirect | CWE-601 |
| `POST /api/xml` | XML external entity expansion | CWE-611 |
| `POST /api/deserialize` | Deserialization of untrusted data | CWE-502 |
| `GET /api/hash?value=` | Weak MD5 hashing | CWE-328 |
| `POST /api/login` | Hard-coded credential and log injection | CWE-798, CWE-117 |

The vulnerable code is intentionally direct so data-flow analyzers can connect
Spring request parameters to their sinks. Dependencies themselves are kept current;
the exercise is in the application source, not in downloading historically unsafe
libraries.

## Build and test

Prerequisites: JDK 17 or newer and Maven 3.9 or newer.

```bash
mvn clean test
```

To run the lab on loopback only:

```bash
mvn spring-boot:run
```

Then check `http://127.0.0.1:8080/api/status`. Do not test dangerous payloads on
systems or data you do not own.

## CodeQL

With the CodeQL CLI installed and a Java query pack available:

```bash
codeql database create codeql-db --language=java --command="mvn clean package -DskipTests"
codeql database analyze codeql-db java-code-scanning.qls --format=sarif-latest --output=results.sarif
```

The exact query-suite path can vary by CodeQL CLI installation. In GitHub, enabling
default setup for CodeQL on this repository is the simplest alternative.

## Agent exercise

Ask a code-review agent to identify vulnerabilities, cite the source and sink, map
each finding to a CWE, propose a fix, and add a regression test. Keep this original
branch as the vulnerable baseline and apply fixes on a separate branch.