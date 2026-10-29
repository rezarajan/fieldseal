{
  description = "Fieldseal: pinned build environment (format core, CLI, runtimes, authority tools)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Builds the Rust workspace in the store: dependencies are compiled once into
    # their own derivation, which CI caches, so a change rebuilds only Fieldseal's crates.
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # Keep these in step with app/build.gradle.kts (compileSdk, buildToolsVersion, ndkVersion).
      android = {
        platform = "36";
        buildTools = "36.1.0";
        ndk = "28.2.13676358"; # r28c: 16 KB page alignment by default
        minSdk = "29";
      };

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (mkEnv system));

      mkEnv =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
            config = {
              allowUnfree = true;
              # Using the Android SDK means accepting Google's SDK licence.
              android_sdk.accept_license = true;
            };
          };
          inherit (pkgs.stdenv) isLinux isDarwin;

          # Google ships Linux SDK/NDK host tools for x86_64 only. On aarch64-linux the
          # Android parts come from the container instead (see docs/reference/toolchain.md, "Platform support").
          hasAndroidHost = system != "aarch64-linux";
          # The emulator runs natively on x86_64 Linux and on both kinds of Mac.
          hasEmulator = system != "aarch64-linux";
          emulatorAbi = if system == "aarch64-darwin" then "arm64-v8a" else "x86_64";

          sdkFor =
            extra:
            (pkgs.androidenv.composeAndroidPackages (
              {
                platformVersions = [ android.platform ];
                buildToolsVersions = [ android.buildTools ];
                includeSources = false;
              }
              // extra
            )).androidsdk;

          androidSdk = sdkFor {
            includeNDK = true;
            ndkVersions = [ android.ndk ];
            includeEmulator = false;
            includeSystemImages = false;
          };

          # Emulator and a Google APIs system image; large, so only in the `emulator` shell.
          androidSdkEmulator = sdkFor {
            includeNDK = false;
            includeEmulator = true;
            includeSystemImages = true;
            systemImageTypes = [ "google_apis" ];
            abiVersions = [ emulatorAbi ];
          };

          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          python = pkgs.python312;

          # The Rust checks CI runs on every pull request, as store derivations:
          # `nix flake check` or `nix build .#checks.<system>.<name>`.
          craneLib = (crane.mkLib pkgs).overrideToolchain rust;
          workspaceSrc = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./architecture.toml
              ./crates
              ./examples
              ./tests
              ./tools/check-architecture.py
              ./tools/demo-pipeline.sh
              ./tools/check-coverage.py
              ./docs/reference/spec
              ./docs/reference/conformance.md
            ];
          };
          # Vendored crates as real copies, not symlinks: askama (used by uniffi_bindgen)
          # resolves its templates with paths that break across crane's symlinked vendor tree.
          vendorLinked = craneLib.vendorCargoDeps { src = workspaceSrc; };
          vendorCopied = pkgs.runCommand "fieldseal-vendor" { } ''
            cp -rL ${vendorLinked} $out
            chmod -R u+w $out
            substituteInPlace $out/config.toml --replace-fail ${vendorLinked} $out
          '';
          workspaceArgs = {
            src = workspaceSrc;
            cargoVendorDir = vendorCopied;
            pname = "fieldseal";
            version = "0.1.0";
            strictDeps = true;
            # opa: the OPA adapter's conformance tests run against the real engine.
            nativeBuildInputs = [
              python
              pkgs.open-policy-agent
              # The demo-pipeline test (CLI-006) runs tools/demo-pipeline.sh.
              pkgs.bash
              pkgs.coreutils
            ];
            cargoExtraArgs = "--locked --workspace";
          };
          # Every third-party crate, compiled once; cached by CI and reused by the checks.
          cargoArtifacts = craneLib.buildDepsOnly workspaceArgs;
          checks = {
            clippy = craneLib.cargoClippy (
              workspaceArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- -D warnings";
              }
            );
            tests = craneLib.cargoTest (workspaceArgs // { inherit cargoArtifacts; });
            architecture = craneLib.mkCargoDerivation (
              workspaceArgs
              // {
                inherit cargoArtifacts;
                pnameSuffix = "-architecture";
                doInstallCargoArtifacts = false;
                buildPhaseCargoCommand = "python3 tools/check-architecture.py && python3 tools/check-coverage.py";
                installPhaseCommand = "mkdir -p $out";
              }
            );
          };
          fieldsealCli = craneLib.buildPackage (
            workspaceArgs
            // {
              inherit cargoArtifacts;
              cargoExtraArgs = "--locked -p fieldseal-cli";
              doCheck = false;
              meta.mainProgram = "fieldseal";
            }
          );

          # The services of the local stack (deploy/local), built once with crane and shared
          # by the images below. Each is one binary; the images add nothing else.
          serviceBin =
            pname: package:
            craneLib.buildPackage (
              workspaceArgs
              // {
                inherit cargoArtifacts pname;
                cargoExtraArgs = "--locked -p ${package} --bin ${pname}";
                doCheck = false;
                meta.mainProgram = pname;
              }
            );
          factoryBin = serviceBin "fieldseal-factory" "fieldseal-factory";
          intakeBin = serviceBin "fieldseal-intake" "fieldseal-intake-app";
          translogBin = serviceBin "fieldseal-translog" "fieldseal-translog";
          webServerBin = serviceBin "fieldseal-web" "fieldseal-web";

          # The browser device: the format core compiled to WebAssembly (ADR 0036). The target is
          # built with its own dependency derivation (the host's artefacts are for another
          # target); wasm-bindgen-cli in nixpkgs must match the crate's `=` pin exactly.
          wasmArgs = workspaceArgs // {
            pname = "fieldseal-wasm";
            cargoExtraArgs = "--locked -p fieldseal-wasm --target wasm32-unknown-unknown";
            CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
            doCheck = false;
          };
          wasmArtifacts = craneLib.buildDepsOnly wasmArgs;
          wasmModule = craneLib.buildPackage (
            wasmArgs
            // {
              cargoArtifacts = wasmArtifacts;
              doNotPostBuildInstallCargoBinaries = true;
              installPhaseCommand = "mkdir -p $out && cp target/wasm32-unknown-unknown/release/fieldseal_wasm.wasm $out/";
            }
          );
          wasmBundle = pkgs.runCommand "fieldseal-wasm-bundle" { nativeBuildInputs = [ pkgs.wasm-bindgen-cli ]; } ''
            wasm-bindgen --target web --out-dir $out --out-name fieldseal_wasm ${wasmModule}/fieldseal_wasm.wasm
          '';
          # The showcase web app with the WebAssembly bundle and the examples, so that
          # `nix run path:.#fieldseal-web` works with no arguments (development only).
          webExamples = pkgs.lib.fileset.toSource {
            root = ./examples;
            fileset = ./examples;
          };
          webApp = pkgs.runCommand "fieldseal-web" { nativeBuildInputs = [ pkgs.makeWrapper ]; meta.mainProgram = "fieldseal-web"; } ''
            mkdir -p $out/bin
            makeWrapper ${webServerBin}/bin/fieldseal-web $out/bin/fieldseal-web \
              --set-default FIELDSEAL_ENVIRONMENT development \
              --set-default FIELDSEAL_WEB_WASM_DIR ${wasmBundle} \
              --set-default FIELDSEAL_WEB_EXAMPLES_DIR ${webExamples}
          '';
          # OCI images for the local stack: a layered image of the binary and nothing else
          # (no shell, no package manager), configured only by its environment. Linux only:
          # `docker load < $(nix build .#factory-image --print-out-paths)`. Nothing here is pushed anywhere.
          serviceImage =
            name: bin: ports: mounts:
            pkgs.dockerTools.buildLayeredImage {
              inherit name;
              tag = "local";
              contents = [
                bin
                pkgs.cacert
              ];
              # The mount points are owned by the service user, so a fresh named volume mounted
              # there is writable (both Docker and Podman copy the ownership up). Every image that
              # mounts a shared volume (`/authority` among them) must agree, because compose
              # creates the containers together and the first to mount a fresh volume sets it.
              fakeRootCommands = ''
                for d in ${pkgs.lib.concatStringsSep " " mounts}; do
                  mkdir -p ".$d"
                  chown -R 10001:10001 ".$d"
                  # The roster store and the issued-roster record both refuse a directory that group or others can reach (the issued rosters carry the same data). Factory and intake run as uid 10001, so intake can still read the owner-only files.
                  case "$d" in /rosters|/issued) chmod 0700 ".$d" ;; esac
                done
              '';
              config = {
                Entrypoint = [ "${bin}/bin/${bin.pname}" ];
                ExposedPorts = pkgs.lib.genAttrs (map (port: "${toString port}/tcp") ports) (_: { });
                Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
                User = "10001:10001";
              };
            };
          # The web app's image: the binary, the WebAssembly bundle and the examples, nothing
          # else; non-root, run it with a read-only root filesystem like the others.
          webImage = pkgs.dockerTools.buildLayeredImage {
            name = "fieldseal-web";
            tag = "local";
            # In the stack (FIELDSEAL_WEB_STACK=true) the device gets its bundle from the factory;
            # the app builds none, so the image holds no CLI.
            contents = [
              webServerBin
              pkgs.cacert
            ];
            fakeRootCommands = ''
              mkdir -p tmp authority published rosters
              chmod 1777 tmp
              # Owned by the service user as in every image that mounts these volumes: a fresh
              # named volume takes the ownership of the first image that mounts it.
              chown 10001:10001 authority published
              # The roster store's directory, as in the factory image: owner-only, read here.
              chmod 0700 rosters
              chown 10001:10001 rosters
            '';
            config = {
              Entrypoint = [ "${webServerBin}/bin/fieldseal-web" ];
              ExposedPorts."8090/tcp" = { };
              Env = [
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                "FIELDSEAL_WEB_WASM_DIR=${wasmBundle}"
                "FIELDSEAL_WEB_EXAMPLES_DIR=${webExamples}"
                "FIELDSEAL_WEB_BIND=0.0.0.0:8090"
              ];
              User = "10001:10001";
            };
          };

          # The stack's scripts and examples, as /opt/fieldseal in the CLI and demo images.
          stackOpt = pkgs.runCommand "fieldseal-stack-opt" { nativeBuildInputs = [ pkgs.bash ]; } ''
            mkdir -p $out/opt/fieldseal/tools
            for f in init demo enroll browser; do cp ${./tools}/stack-$f.sh $out/opt/fieldseal/tools/; done
            cp ${./tools/local-stack-passkey.py} $out/opt/fieldseal/tools/local-stack-passkey.py
            cp -r ${./examples} $out/opt/fieldseal/examples
            chmod -R u+w $out
            patchShebangs $out/opt/fieldseal/tools
          '';
          stackShellTools = [
            pkgs.bash
            pkgs.coreutils
            pkgs.findutils
            pkgs.gnused
            pkgs.gnugrep
            pkgs.gawk
            pkgs.jq
            pkgs.cacert
          ];
          stackPython = python.withPackages (p: [ p.websockets ]);
          # Same user as the services; /device, /authority and /landing are volume mount points.
          stackToolImage =
            name: extra: env: entrypoint:
            pkgs.dockerTools.buildLayeredImage {
              inherit name;
              tag = "local";
              contents = [
                fieldsealCli
                stackOpt
              ]
              ++ stackShellTools
              ++ extra;
              fakeRootCommands = ''
                mkdir -p tmp authority device landing clistate published out
                chmod 1777 tmp
                chown 10001:10001 authority device landing clistate published out
              '';
              config = {
                Entrypoint = entrypoint;
                Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ] ++ env;
                User = "10001:10001";
                WorkingDir = "/opt/fieldseal";
              };
            };
          images = pkgs.lib.optionalAttrs isLinux {
            web-image = webImage;
            factory-image = serviceImage "fieldseal-factory" factoryBin [ 8080 ]
                [
                  "/authority"
                  "/state/factory"
                  "/rosters"
                  "/bundles"
                  "/issued"
                ];
            intake-image =
              serviceImage "fieldseal-intake" intakeBin [ 8480 8481 ]
                [
                  "/authority"
                  "/landing"
                  "/submissions"
                  "/published"
                  "/issued"
                ];
            translog-image = serviceImage "fieldseal-translog" translogBin [ 8080 ] [
              "/authority"
              "/data/log"
            ];
            cli-image = stackToolImage "fieldseal-cli" [ ] [ ] [ "/opt/fieldseal/tools/stack-init.sh" ];
            demo-image =
              stackToolImage "fieldseal-demo"
                [
                  pkgs.curl
                  stackPython
                  pkgs.chromium
                  pkgs.dejavu_fonts
                ]
                [
                  "HOME=/tmp/home"
                  # Chromium floods its stderr with text errors when no font is found.
                  "FONTCONFIG_FILE=${pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; }}"
                ]
                [ "/opt/fieldseal/tools/stack-demo.sh" ];
          };

          # ELF inspection that works on any host (GNU readelf/objdump are Linux-centric,
          # and putting GNU ld on PATH would break host linking on macOS).
          elfTools = pkgs.runCommand "fieldseal-elf-tools" { } ''
            mkdir -p $out/bin
            for t in readelf objdump strings; do
              ln -s ${pkgs.llvmPackages.llvm}/bin/llvm-$t $out/bin/$t
            done
          '';

          commonTools = [
            # Rust core
            rust
            pkgs.cargo-ndk # cross-compile the core for Android ABIs
            pkgs.cargo-deny # licence and advisory checks
            pkgs.cargo-nextest
            pkgs.wasm-bindgen-cli # WebAssembly bundle of the browser device; its version must equal the wasm-bindgen crate's
            pkgs.maturin # Python wheel of the core for HQ
            pkgs.zig # lets maturin target manylinux glibc from any host

            # Policy engine: the OPA adapter (crates/adapters/opa) runs `opa eval`
            pkgs.open-policy-agent

            # Android app (JVM side works everywhere)
            pkgs.jdk21
            pkgs.gradle_9

            # HQ intake tool
            python
            pkgs.uv

            # Portability checks and scripting. GNU userland so the scripts behave
            # the same on macOS as on Linux.
            elfTools
            pkgs.file
            pkgs.unzip
            pkgs.zip
            pkgs.coreutils
            pkgs.findutils
            pkgs.gnugrep
            pkgs.gnused
            pkgs.gawk
            pkgs.git
            pkgs.jq
          ];

          # The local stack (justfile, tools/stack-*.sh): everything but the container engine daemon.
          stackTools = [
            pkgs.just
            pkgs.curl
            pkgs.shellcheck
            (python.withPackages (p: [ p.websockets ]))
          ]
          ++ pkgs.lib.optionals isLinux [
            pkgs.docker-client
            pkgs.docker-compose
            pkgs.podman
            pkgs.podman-compose
            pkgs.conmon
            pkgs.crun
            pkgs.netavark
            pkgs.aardvark-dns
            pkgs.passt
            pkgs.slirp4netns
            pkgs.fuse-overlayfs
            pkgs.chromium
          ];

          linuxTools = pkgs.lib.optionals isLinux [
            python.pkgs.auditwheel # manylinux verification; Linux only
            pkgs.patchelf
          ];

          sdkRoot = "${androidSdk}/libexec/android-sdk";

          androidEnv = pkgs.lib.optionalAttrs hasAndroidHost (
            {
              ANDROID_HOME = sdkRoot;
              ANDROID_SDK_ROOT = sdkRoot;
              ANDROID_NDK_HOME = "${sdkRoot}/ndk/${android.ndk}";
              ANDROID_NDK_ROOT = "${sdkRoot}/ndk/${android.ndk}";
            }
            // pkgs.lib.optionalAttrs isLinux {
              # Gradle downloads its own aapt2, which cannot run without an FHS layout.
              # Point it at the patched aapt2 from the pinned SDK instead.
              GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdkRoot}/build-tools/${android.buildTools}/aapt2";
            }
          );

          env = {
            JAVA_HOME = pkgs.jdk21.home;
            FIELDSEAL_ANDROID_MIN_SDK = android.minSdk;
            FIELDSEAL_ANDROID_BUILD_TOOLS = android.buildTools;
            FIELDSEAL_ANDROID_HOST = if hasAndroidHost then "1" else "0";
            # Keep uv and maturin from picking up a system Python.
            UV_PYTHON = "${python}/bin/python3";
            UV_PYTHON_DOWNLOADS = "never";
          }
          // androidEnv;
        in
        {
          inherit
            system
            pkgs
            hasEmulator
            emulatorAbi
            androidSdkEmulator
            checks
            fieldsealCli
            images
            factoryBin
            intakeBin
            translogBin
            webApp
            wasmBundle
            ;

          shell = pkgs.mkShell (
            {
              # cargo-nextest runs the test binaries in parallel (`just test`, the 20 s budget).
              packages = stackTools ++ commonTools ++ linuxTools ++ [ pkgs.cargo-nextest pkgs.yamllint pkgs.ruff pkgs.taplo pkgs.actionlint pkgs.rust-analyzer pkgs.yaml-language-server pkgs.shellcheck ] ++ pkgs.lib.optional hasAndroidHost androidSdk;
              shellHook = ''
                echo "Fieldseal build shell (${system}): rust $(rustc --version | cut -d' ' -f2), JDK 21, Python ${python.version}"
                ${
                  if hasAndroidHost then
                    ''echo "Android: SDK ${android.platform}, build-tools ${android.buildTools}, NDK ${android.ndk}"''
                  else
                    ''echo "Android SDK/NDK: not available on ${system}; build the APK with the container (see docs/how-to/build-and-check.md)"''
                }
              '';
            }
            // env
          );
        };
    in
    {
      devShells = forAllSystems (
        e:
        {
          default = e.shell;
        }
        // e.pkgs.lib.optionalAttrs e.hasEmulator {
          # nix develop path:.#emulator  (see docs/explanation/build-system.md, "The emulator in practice")
          emulator = e.pkgs.mkShell {
            packages = [
              e.androidSdkEmulator
              e.pkgs.jdk21
            ];
            ANDROID_HOME = "${e.androidSdkEmulator}/libexec/android-sdk";
            ANDROID_SDK_ROOT = "${e.androidSdkEmulator}/libexec/android-sdk";
            ANDROID_USER_HOME = ".android";
            ANDROID_AVD_HOME = ".android/avd";
            JAVA_HOME = e.pkgs.jdk21.home;
            FIELDSEAL_ANDROID_PLATFORM = android.platform;
            FIELDSEAL_EMULATOR_ABI = e.emulatorAbi;
          };
        }
      );

      checks = forAllSystems (e: e.checks);

      # nix run path:.#fieldseal -- instrument validate examples/surveys/school-meals-baseline/instrument.yaml
      packages = forAllSystems (
        e:
        {
          fieldseal = e.fieldsealCli;
          default = e.fieldsealCli;
          fieldseal-factory = e.factoryBin;
          fieldseal-intake = e.intakeBin;
          fieldseal-translog = e.translogBin;
          fieldseal-web = e.webApp;
          fieldseal-wasm = e.wasmBundle;
        }
        // e.images
      );

      formatter = forAllSystems (e: e.pkgs.nixfmt-rfc-style);
    };
}
