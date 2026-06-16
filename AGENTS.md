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

## Local Development

- Set `DEV_MODE=true` to run the binary outside a Kubernetes cluster.
- In dev mode it uses `fake.NewSimpleClientset()` for K8s storage and auto-generates a throwaway `age` master key if `MASTER_KEY` is not set, so the vault starts unlocked and the Web UI is immediately usable.
- Example:
  ```bash
  GOEXPERIMENT=runtimesecret DEV_MODE=true ./csi-secret-age
  ```

## Web UI

- **Tree navigation:** The home page (`/`) shows a folder tree with breadcrumb navigation based on path segments (`/db/postgres/...`).
- **Folder ACLs:** You can create folder nodes (with the "Create as folder" checkbox) that have ACLs but no secret value. When navigating into a folder, its ACLs are shown at the top.
- **Entry detail:** Clicking a leaf entry opens `/entry?path=...` showing the masked value, ACLs, and a delete button.
- **Blind-write:** Values are never displayed in plaintext; the UI always shows `********`.
- **Path conflicts:** The UI validates that a path cannot be both a folder and a secret, and that leaf secrets cannot have children.

## Repo Hygiene

- `key.txt` is a local age secret key used in development. It should never be committed.
- No `Dockerfile` in repo yet; image is referenced in `deploy.yaml` as `age-vault-csi:latest`.
