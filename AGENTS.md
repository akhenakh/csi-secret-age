# AGENTS.md

## Project Overview
Single-binary Go CSI provider for Kubernetes. All code lives in one package (`main`) in `main.go` with tests in `main_test.go`. No sub-packages, no build scripts, no CI.

## Build & Run

- **Go version:** `go 1.26.3` (mod file pins this).
- **Build (with security experiment):**
  ```bash
  GOEXPERIMENT=runtimesecret go build -o csi-secret-age .
  ```
  Without `GOEXPERIMENT=runtimesecret`, the binary still compiles but memory-wiping is inactive and a warning is logged at startup.
- **Run tests:**
  ```bash
  go test ./...
  ```
  Tests use `k8s.io/client-go/kubernetes/fake` (no real cluster required).

## Architecture Notes

- **Single-package design:** Everything is in `package main`. There are no sub-packages or internal packages.
- **Entry point:** `main.go` wires a `VaultManager` (crypto + K8s storage), a gRPC CSI server, and an HTTP admin UI.
- **Runtime/secret experiment:** Any code handling plaintext must run inside `secret.Do(func(){ ... })`. The Go GC then zeroes the memory pages afterward. This is not optional for the security claims—if you add secret-handling code, wrap it in `secret.Do`.
- **No generated code:** No protobuf generation, no `go generate`, no code generation step.
- **No linter/typecheck configs:** No `.golangci.yml`, `Makefile`, or CI workflows. Standard `go vet` and `go test` are the only verification steps.

## Deployment Context

- `deploy.yaml` is the hand-written Kubernetes manifest (RBAC + DaemonSet). It is not generated.
- The provider expects the Secrets Store CSI Driver to be pre-installed in the cluster (see README for helm command).
- The DaemonSet uses `hostNetwork: true` and a Unix socket at `/csi/agevault.sock`.

## Testing Conventions

- Tests generate a throwaway `age` identity via `age.GenerateX25519Identity()` (see `generateTestMasterKey`).
- `fake.NewSimpleClientset()` is used for all K8s interactions; no env or running cluster needed.
- `getTestLogger()` discards logs to keep test output clean.
- Table-driven tests with `testify/assert` and `require`.

## Repo Hygiene

- `key.txt` is a local age secret key used in development. It should never be committed.
- No `Dockerfile` in repo yet; image is referenced in `deploy.yaml` as `age-vault-csi:latest`.
