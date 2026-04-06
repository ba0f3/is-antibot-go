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

## Style

- Comments and identifiers in **English**.
- Prefer matching existing patterns in `is_antibot.go` (closure helpers, `patternMatcher`, `createResult`).
- Run `gofmt` on edited Go files.
