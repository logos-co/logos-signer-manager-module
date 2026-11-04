{
  description = "mock_device_signer — doc-test fixture: a signer that waits for its device's button, or answers wrong on purpose.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # logos.wallets/1 (wallets.lidl): `enroll` adds the device's seed to the signer manager.
    logos-signer-interface = {
      url = "github:logos-co/logos-signer-interface/d8cfff84327c9b2b5cdb9702d1c4217cad567cee";
      flake = false;
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
