{ pkgs ? import <nixpkgs> {}
}:

pkgs.stdenv.mkDerivation rec {
  name = "powerdns-api";

  nativeBuildInputs = [
    pkgs.pkg-config
    pkgs.libsodium
  ];

  buildInputs = [
    pkgs.zlib
    pkgs.ghc
    pkgs.haskellPackages.haskell-language-server
    pkgs.which
    pkgs.cabal-install
    pkgs.haskellPackages.cabal-plan
  ];

  shellHook = ''
    export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath buildInputs}:$LD_LIBRARY_PATH
    export LANG=en_US.UTF-8
  '';
}
