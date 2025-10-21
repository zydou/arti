{
  description = "A dev environment for Arti";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.rustup

            pkgs.pkg-config
            pkgs.openssl
            pkgs.sqlite
            pkgs.git

            pkgs.docker
            pkgs.grcov

            pkgs.cargo-audit
            pkgs.cargo-fuzz
            pkgs.cargo-license
            pkgs.cargo-sort

            pkgs.python3Packages.lxml
            pkgs.python3Packages.toml
            pkgs.python3Packages.beautifulsoup4

            pkgs.shellcheck

            pkgs.perl

            pkgs.llvmPackages.clang
          ];

          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          RUSTUP_TOOLCHAIN="1.86";

          shellHook = ''
            echo "⚠️ The Nix Development Shell is maintained by the community ⚠️"
            echo ""
            echo "We include it here for convenience but the core team lacks the capacity to maintain it themselves."
            echo ""
            echo "Therefore things may break in the future and stability is not guaranteed."
            echo "Patches are more than welcome though! ❤️"
          '';
        };
      }
    );
}
