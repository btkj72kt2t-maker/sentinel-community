# AllAboutBugBounty mapping

Source reviewed: <https://github.com/daffainfo/AllAboutBugBounty>

The source is a community knowledge collection organized around vulnerability
classes, bypass themes, technology notes, reconnaissance, and checklists. It is
not a vetted registry of 1,000 security tools. Sentinel uses its taxonomy as a
coverage input and does not ingest or execute its payload examples.

Mapped themes include access control/IDOR, authentication and account recovery,
OAuth and JWT, SQL/NoSQL/SSI injection, XSS/CSRF, SSRF, files and paths, request
smuggling and header handling, cache poisoning/deception, exposed source and
secrets, business logic, availability controls, and common platform reviews.

Sentinel adds API/GraphQL/WebSocket, source and binary analysis, dependency and
supply-chain review, cloud/container/Kubernetes, network/TLS, mobile, firmware,
wireless, and offline research families. Each family declares its permitted
assessment mode. Potentially disruptive validation stays manual or lab-only.

The capability catalogue is deliberately curated. A raw count is not a quality
metric: duplicate, abandoned, or unreviewed tools increase operational and
supply-chain risk. Only tools with reviewed Sentinel adapters can execute; mere
catalogue presence never grants execution.
