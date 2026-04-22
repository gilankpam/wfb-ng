{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "wfb-ng-dev";

  nativeBuildInputs = with pkgs; [
    pkg-config
    gnumake
    gcc
    lsb-release
  ];

  buildInputs = with pkgs; [
    libsodium
    libpcap
    libevent
    catch2_3
    gst_all_1.gst-rtsp-server
    gst_all_1.gstreamer
    (python3.withPackages (ps: with ps; [
      twisted
      pyroute2
      pyserial
      msgpack
      jinja2
      pyyaml
      virtualenv
      setuptools
    ]))
  ];
}
