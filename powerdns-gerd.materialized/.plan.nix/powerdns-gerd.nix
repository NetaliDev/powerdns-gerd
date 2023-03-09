{ system
  , compiler
  , flags
  , pkgs
  , hsPkgs
  , pkgconfPkgs
  , errorHandler
  , config
  , ... }:
  {
    flags = {};
    package = {
      specVersion = "3.0";
      identifier = { name = "powerdns-gerd"; version = "0.1.2"; };
      license = "BSD-3-Clause";
      copyright = "";
      maintainer = "dminuoso+git@icloud.com";
      author = "";
      homepage = "";
      url = "";
      synopsis = "";
      description = "";
      buildType = "Simple";
      isLocal = true;
      detailLevel = "FullDetails";
      licenseFiles = [ "LICENSE" ];
      dataDir = ".";
      dataFiles = [];
      extraSrcFiles = [ "CHANGELOG.md" ];
      extraTmpFiles = [];
      extraDocFiles = [];
      };
    components = {
      sublibs = {
        "powerdns-gerd-lib" = {
          depends = [
            (hsPkgs."base" or (errorHandler.buildDepError "base"))
            (hsPkgs."powerdns" or (errorHandler.buildDepError "powerdns"))
            (hsPkgs."warp" or (errorHandler.buildDepError "warp"))
            (hsPkgs."attoparsec" or (errorHandler.buildDepError "attoparsec"))
            (hsPkgs."bytestring" or (errorHandler.buildDepError "bytestring"))
            (hsPkgs."config-schema" or (errorHandler.buildDepError "config-schema"))
            (hsPkgs."config-value" or (errorHandler.buildDepError "config-value"))
            (hsPkgs."containers" or (errorHandler.buildDepError "containers"))
            (hsPkgs."gitrev" or (errorHandler.buildDepError "gitrev"))
            (hsPkgs."http-client" or (errorHandler.buildDepError "http-client"))
            (hsPkgs."http-client-tls" or (errorHandler.buildDepError "http-client-tls"))
            (hsPkgs."http-types" or (errorHandler.buildDepError "http-types"))
            (hsPkgs."libsodium" or (errorHandler.buildDepError "libsodium"))
            (hsPkgs."monad-logger" or (errorHandler.buildDepError "monad-logger"))
            (hsPkgs."mtl" or (errorHandler.buildDepError "mtl"))
            (hsPkgs."optparse-applicative" or (errorHandler.buildDepError "optparse-applicative"))
            (hsPkgs."template-haskell" or (errorHandler.buildDepError "template-haskell"))
            (hsPkgs."pretty" or (errorHandler.buildDepError "pretty"))
            (hsPkgs."servant" or (errorHandler.buildDepError "servant"))
            (hsPkgs."servant-client" or (errorHandler.buildDepError "servant-client"))
            (hsPkgs."servant-client-core" or (errorHandler.buildDepError "servant-client-core"))
            (hsPkgs."servant-server" or (errorHandler.buildDepError "servant-server"))
            (hsPkgs."text" or (errorHandler.buildDepError "text"))
            (hsPkgs."transformers" or (errorHandler.buildDepError "transformers"))
            (hsPkgs."unliftio" or (errorHandler.buildDepError "unliftio"))
            (hsPkgs."unix" or (errorHandler.buildDepError "unix"))
            (hsPkgs."wai" or (errorHandler.buildDepError "wai"))
            (hsPkgs."iproute" or (errorHandler.buildDepError "iproute"))
            (hsPkgs."dns-patterns" or (errorHandler.buildDepError "dns-patterns"))
            ];
          buildable = true;
          modules = [
            "PowerDNS/Gerd/API"
            "PowerDNS/Gerd/User"
            "PowerDNS/Gerd/User/Types"
            "PowerDNS/Gerd/Types"
            "PowerDNS/Gerd/Permission"
            "PowerDNS/Gerd/Permission/Types"
            "Paths_powerdns_gerd"
            "PowerDNS/Gerd/Options"
            "PowerDNS/Gerd/Server"
            "PowerDNS/Gerd/Server/Endpoints"
            "PowerDNS/Gerd/Config"
            "PowerDNS/Gerd/CmdDigest"
            "PowerDNS/Gerd/CmdConfig"
            "PowerDNS/Gerd/CmdVersion"
            "PowerDNS/Gerd/CmdServer"
            "PowerDNS/Gerd/Utils"
            ];
          hsSourceDirs = [ "lib" ];
          };
        };
      exes = {
        "powerdns-gerd" = {
          depends = [
            (hsPkgs."base" or (errorHandler.buildDepError "base"))
            (hsPkgs."powerdns" or (errorHandler.buildDepError "powerdns"))
            (hsPkgs."powerdns-gerd".components.sublibs.powerdns-gerd-lib or (errorHandler.buildDepError "powerdns-gerd:powerdns-gerd-lib"))
            ];
          buildable = true;
          hsSourceDirs = [ "app" ];
          mainPath = [ "Main.hs" ];
          };
        };
      tests = {
        "powerdns-gerd-test" = {
          depends = [
            (hsPkgs."base" or (errorHandler.buildDepError "base"))
            (hsPkgs."powerdns" or (errorHandler.buildDepError "powerdns"))
            (hsPkgs."warp" or (errorHandler.buildDepError "warp"))
            (hsPkgs."HUnit" or (errorHandler.buildDepError "HUnit"))
            (hsPkgs."tasty" or (errorHandler.buildDepError "tasty"))
            (hsPkgs."tasty-hunit" or (errorHandler.buildDepError "tasty-hunit"))
            (hsPkgs."servant-client" or (errorHandler.buildDepError "servant-client"))
            (hsPkgs."servant-client-core" or (errorHandler.buildDepError "servant-client-core"))
            (hsPkgs."http-client" or (errorHandler.buildDepError "http-client"))
            (hsPkgs."http-types" or (errorHandler.buildDepError "http-types"))
            (hsPkgs."powerdns-gerd".components.sublibs.powerdns-gerd-lib or (errorHandler.buildDepError "powerdns-gerd:powerdns-gerd-lib"))
            (hsPkgs."text" or (errorHandler.buildDepError "text"))
            (hsPkgs."unliftio" or (errorHandler.buildDepError "unliftio"))
            (hsPkgs."monad-logger" or (errorHandler.buildDepError "monad-logger"))
            (hsPkgs."call-stack" or (errorHandler.buildDepError "call-stack"))
            ];
          buildable = true;
          modules = [ "Utils" ];
          hsSourceDirs = [ "test" ];
          mainPath = [ "Spec.hs" ];
          };
        };
      };
    } // rec { src = (pkgs.lib).mkDefault ../.; }