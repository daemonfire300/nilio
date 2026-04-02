# Agent Notes

This repository ships a Nix flake for development. Use it before running Go or `make`
commands so the toolchain matches `go.mod`.

## Standard workflow

Enter the shell from the repository root:

```sh
nix develop
```

If the flake files are still untracked in Git, use:

```sh
nix develop "path:$PWD"
```

For one-off commands, prefer:

```sh
nix develop -c go test ./...
nix develop -c make build
```

## What the shell provides

The default dev shell includes:

- `go_1_25` (current `nixpkgs` package, compatible with this repo's `go 1.24` minimum)
- `gopls`
- `golangci-lint`
- `gnumake`
- `git`
- `gcc`
- `typos`

It also sets:

- `CGO_ENABLED=0` by default, matching the common build path in `Makefile`
- `GOTOOLCHAIN=local` so the Nix-provided Go toolchain is used as-is
- `GOPATH=$PWD/.gopath`
- `GOBIN=$PWD/.gopath/bin`

## Agent guidance

- Always prefer adding files to git instead of using nix flake path references
- Commit changes that have to be run through nix/flake to git
- Prefer the flake shell over any system-installed Go toolchain.
- Run build, test, and lint commands through `nix develop -c ...` unless you are already
  inside `nix develop`.
- If you change `flake.nix`, refresh the lock file with `nix flake lock` or
  `nix flake lock --update-input nixpkgs`, then verify with `nix develop -c go version`.
