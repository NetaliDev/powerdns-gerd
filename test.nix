let defaultComponents = (import ./project.nix { mode = "dynamic"; }).powerdns-gerd.components;
    localComponents = (import ./local.nix).powerdns-gerd.components;
in {
  default = import ./test {
    powerdns-gerd-test = defaultComponents.tests.powerdns-gerd-test;
    powerdns-gerd = defaultComponents.exes.powerdns-gerd;
  };
  local = import ./test {
    powerdns-gerd-test = localComponents.tests.powerdns-gerd-test;
    powerdns-gerd = localComponents.exes.powerdns-gerd;
  };
}
