{
  description = "Minimal development shell for the MinIO Go repository";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              bashInteractive
              gcc
              git
              go_1_25
              golangci-lint
              gopls
              gnumake
              typos
            ];

            shellHook = ''
              export CGO_ENABLED=0
              export GOTOOLCHAIN=local
              export GOPATH="$PWD/.gopath"
              export GOBIN="$GOPATH/bin"
              export PATH="$GOBIN:$PATH"
              mkdir -p "$GOBIN"
            '';
          };
        }
      );
    };
}
