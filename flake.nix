{
  description = "RTLPlayground firmware build environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }: {
    devShells = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            binutils
            bison
            bzip2
            curl
            flex
            gcc
            git
            gnumake
            patch
            pkg-config
            python3
            xxd
          ];

          buildInputs = with pkgs; [
            boost
            json_c
            zlib
          ];

          # SDCC's bundled preprocessor fails Nix's format-security check.
          hardeningDisable = [ "format" ];

          # The Makefile selects patched SDCC only when CC has its make default.
          shellHook = ''
            unset CC
          '';
        };
      }
    );
  };
}
