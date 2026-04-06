---
name: merge-upstream-release
description: Ports releases from microlinkhq/is-antibot (JavaScript) into this Go repo by manual diff review—no git merge from upstream. Use when the user asks to merge, port, sync, or align with an upstream version, tag range (e.g. v1.6.2...v1.7.0), or is-antibot release.
---

# Merge upstream release (manual port)

## Constraints (non-negotiable)

- **Never** `git merge`, subtree-merge, or add upstream as a subtree of [microlinkhq/is-antibot](https://github.com/microlinkhq/is-antibot). This repo stays a hand-maintained Go port.
- Port only signals from **HTTP responses**: headers, `Set-Cookie`, body/HTML, URL, status code. No browser-only APIs.
- Provider strings: **lowercase**, **hyphens** as in upstream (e.g. `aws-waf`, `cloudflare-turnstile`).
- Match patterns already in `is_antibot.go` (`patternMatcher`, `hasAnyHtml`, `createResult`, etc.). See [AGENTS.md](../../../AGENTS.md) for layout and style.

## Workflow

1. **Identify the delta**
   - From a GitHub compare URL (`base...head` tags) or named tags, determine **exactly** which upstream commits/files changed.
   - If needed, use a **temporary** clone of upstream: `git diff tagOld..tagNew -- src/index.js test/index.js` (full history may be required for merge-base; shallow clones can break `git diff` between tags).

2. **Read upstream changes**
   - Primary: `src/index.js` (detection rules and order).
   - Primary: `test/index.js` (expected behavior).
   - Ignore unless needed elsewhere: `package.json`, `CHANGELOG.md`, `README.md` marketing lists.
   - **Do not** copy `providers/**/*.json` HAR fixtures into this repo; use them only to understand real responses, then encode the same behavior in Go tests.

3. **Implement in Go**
   - Edit `is_antibot.go`: add or adjust rules, preserving order **when practical** relative to upstream so future diffs stay easy.
   - Edit `is_antibot_test.go`: port upstream tests (table-driven or individual `Test*` functions—follow existing file style).

4. **Verify**
   - From repo root: `gofmt -w .`, then `go test ./...`, then `go build -v ./...` (same as CI and [AGENTS.md](../../../AGENTS.md)).

## Checklist

- [ ] Diff reviewed: `index.js` + upstream tests understood
- [ ] Go rules + tests updated; no unrelated refactors
- [ ] `gofmt`, `go test ./...`, `go build -v ./...` all pass

## If the user only gives a compare link

Resolve `base` and `head` tags (or commits), then follow the workflow above. Summarize what was ported (providers, detection type) in the final reply.
