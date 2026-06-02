{ pkgs, ... }: {
  # Disable automatic cachix cache management due to Nix trust issues
  cachix.enable = false;

  # Enable Go development
  languages.go.enable = true;

  # Additional development tools needed for building/managing kubebuilder operators
  packages = [
    pkgs.kubebuilder
    pkgs.kustomize
  ];
}
