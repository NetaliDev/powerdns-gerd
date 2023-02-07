{ powerdns-gerd-test, powerdns-gerd }:

let sources = import ../nix/sources.nix {};
    nixpkgs = import sources.nixpkgs {};
    nixos-lib = import (sources.nixpkgs + "/nixos/lib") {};

    configFile = ./powerdns-gerd.test.conf;
    sqlitePath = "/var/lib/pdns/backend.sqlite";
in

nixos-lib.runTest {
  nodes = {
    pdns = { pkgs, ... }: {
      config = {
        environment.systemPackages = [ powerdns-gerd-test ];
        networking.firewall.allowedTCPPorts = [ 8081 ];

        systemd.services.powerdns-gerd = {
          script = ''
            ${powerdns-gerd}/bin/powerdns-gerd server -c ${configFile}
          '';
          wantedBy = ["multi-user.target"];
          after = ["network-online.target"];
        };

        systemd.services.pdns-init = {
          enable = true;
          script = ''
            ${pkgs.sqlite}/bin/sqlite3 ${sqlitePath} < ${pkgs.pdns}/share/doc/pdns/schema.sqlite3.sql
          '';
          requiredBy = [ "pdns.service" ];
          before = [ "pdns.service" ];
          serviceConfig.Type = "oneshot";
          serviceConfig.User = "pdns";
          serviceConfig.RemainAfterExit = true;
          serviceConfig.StateDirectory = "pdns";
        };
        
        services.powerdns.enable = true;
        services.powerdns.extraConfig = ''
          api=yes
          api-key=secret
          launch=gsqlite3
          gsqlite3-database=${sqlitePath}
        '';
      };
    };
  };

  name = "powerdns-gerd tests";

  hostPkgs = nixpkgs;

  testScript = ''
    pdns.wait_for_unit("powerdns-gerd.service")
    pdns.succeed("powerdns-gerd-test")
  '';
}
