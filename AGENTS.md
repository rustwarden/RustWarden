# graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.

# Version control

- Do not commit or push automatically. Only commit or push when the user explicitly asks. When asked, use a message that says what changed and why.
- If a push is rejected because the remote has new commits, fetch, rebase onto the remote branch, resolve any conflicts yourself, and push again.
- Never force-push.
- Stop and ask only when a conflict is a logic clash: two changes modify the same function or behavior in incompatible ways.

# Versioning

- After each new feature commit, increment the minor version (the middle number) by 1 and reset the patch: 1.1 becomes 1.2, 1.2.1 becomes 1.3.
- After each bug fix commit, increment the patch version (the last number) by 1: 1.2 becomes 1.2.1, 1.2.1 becomes 1.2.2.
- The version lives in Cargo.toml. Keep it in step with each commit.
- On the dev branch, never bump the version to 2.0.0 (or any 2.x). 2.0.0 is reserved for the next main branch build. If a bump would reach it, stop and ask.

# File updates

- Update the changes.md file with new changes. It is a feature log, so you are free to edit existing entries that have changed if needed. Update it after each successful change or feature.
- Several people work on this codebase, so every entry you add or edit must name who made the change, using the git user name of the person you are working for (e.g. connor). Put the name at the start of the entry, such as `- [connor] feat: ...`. When you edit an existing entry, keep the original author's name and add yours if it is a different person.
- README.md is a short overview and FEATURES.md is the full feature list. For user-visible features, add them to FEATURES.md in full, and update README.md only if the short summary or its "What it does" list is affected.

# Project rules

- Every new feature must work in Demo mode as well as Live mode. MockBackend in src/demo.rs mirrors LiveBackend (src/live/mod.rs) behind the Backend trait in src/data.rs, so add the feature to both.
- Never block the UI thread; use background workers.
- Anything that creates firewall rules or QoS policies must tag them as owned by RustWarden and be reversible and removable in bulk.
- Secrets, tokens and webhook URLs are stored with DPAPI (src/sys/dpapi.rs).
- Local-first: no outbound network calls for a feature unless the user has enabled it. New network-using features are off by default.
- Add unit tests for new logic, and run `cargo fmt`, `cargo clippy` and `cargo test` before committing.
- If a prompt asks you to research feasibility first and the result is not viable, stop and ask before implementing an alternative. Do not commit half-working features.
- One commit per feature (so each gets its own minor version bump); fixes found along the way are separate commits with a patch bump.
