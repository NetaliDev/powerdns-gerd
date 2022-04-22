{
  description = "PowerDNS Gerd Authorization Proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    
    powerdns.url = "gitlab:wobcom/haskell%2Fpowerdns";
    powerdns.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, powerdns }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        haskellPackages = pkgs.haskellPackages;

        dontCheck = pkgs.haskell.lib.dontCheck;

        packageName = "powerdns-gerd";
      in {
        packages.${packageName} = dontCheck (
          haskellPackages.callCabal2nix packageName self {
            powerdns = powerdns.defaultPackage.${system};
          }
        );

        defaultPackage = self.packages.${system}.${packageName};

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            haskellPackages.haskell-language-server
            ghcid
            cabal-install
          ];
          inputsFrom = builtins.attrValues self.packages.${system};
        };
      });
}
