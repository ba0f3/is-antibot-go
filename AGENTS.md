# Agent notes

This repository is a **Go port** of the JavaScript library [microlinkhq/is-antibot](https://github.com/microlinkhq/is-antibot). It exposes a single package that detects antibot / challenge responses from HTTP metadata (headers, body/HTML, URL, status code).

## Module

- Import path: `github.com/ba0f3/is-antibot-go`
- Go version: see `go.mod`

## Layout

| File | Role |
|------|------|
| `is_antibot.go` | `Detect(Input) Result` and all provider rules |
| `is_antibot_test.go` | Table-driven and scenario tests |

## Verify changes

From the repo root:

```bash
gofmt -w .
go test ./...
go build -v ./...
```

CI runs the same checks (see `.github/workflows/go.yml`).

## Porting from upstream JS

When aligning behavior with `is-antibot` (Node) or related sources, only port signals derivable from **HTTP responses**: headers, cookies (`Set-Cookie`), response body/HTML, request URL, and status code. Do not rely on browser-only APIs.

Provider identifiers stay **lowercase** with **hyphens** where the JS library uses them (e.g. `cloudflare-turnstile`, `aws-waf`).

### Merging upstream releases (manual port)

Upstream is JavaScript; **do not** `git merge` or subtree-merge [microlinkhq/is-antibot](https://github.com/microlinkhq/is-antibot) into this repository. Align versions by hand:

1. **Pick a version range** (e.g. compare tags `v1.6.2...v1.7.0` on GitHub or `git diff tag1..tag2` in a local clone of upstream).
2. **Inspect the diff** for `src/index.js` and `test/index.js`. Ignore packaging (`package.json`, `CHANGELOG.md`) unless you need release notes elsewhere.
3. **Port each rule** into `is_antibot.go` in the same order as upstream when practical, using existing helpers (`hasAnyHtml`, `patternMatcher`, etc.).
4. **Port matching tests** into `is_antibot_test.go`. Upstream HAR/JSON fixtures under `providers/` are reference captures only; port the **behavior** they illustrate, not the files.
5. Run `gofmt`, `go test ./...`, and `go build -v ./...` from the repo root.

## Style

- Comments and identifiers in **English**.
- Prefer matching existing patterns in `is_antibot.go` (closure helpers, `patternMatcher`, `createResult`).
- Run `gofmt` on edited Go files.
