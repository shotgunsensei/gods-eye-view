---
name: Dependency installation on Replit
description: Preserving imported Node dependency intent when Replit's package installer resolves packages.
---

When installing an imported Node project through Replit's package installer, preserve the dependency ranges declared by the project rather than replacing them with narrower versions.

**Why:** Narrowing a declared range can replace an imported resolved dependency tree with incompatible transitive packages even when installation itself succeeds.

**How to apply:** Read the dependency manifest first, preserve its declared ranges in package-installer requests, and verify the resulting lockfile, build, and tests before accepting changes.