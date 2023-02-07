(import ./local.nix).shellFor {
  tools = {
    cabal = "latest";
    haskell-language-server = "latest";
  };
}
