# Reuse the CI images

CI publishes a builder image (the full toolchain) and an artefacts image (`dist/` only) to GitHub Container Registry. This guide shows how to build on the published toolchain, use it as a shell, or fetch a commit's artefacts without building. The images and their tags are listed in the [toolchain reference](../reference/toolchain.md#continuous-integration).

## Steps

```sh
# Log in once (a personal access token with read:packages; the packages are private with the repo)
echo "$GHCR_TOKEN" | podman login ghcr.io -u <github-user> --password-stdin

# Build locally on top of the published toolchain instead of provisioning one
podman build --build-arg BUILDER_IMAGE=ghcr.io/rezarajan/fieldseal/builder:latest \
  --target artifacts --output type=local,dest=dist .

# Or use the builder image directly as a build shell
podman run --rm -it -v "$PWD":/src -w /src ghcr.io/rezarajan/fieldseal/builder:latest \
  nix develop path:. --command tools/build.sh

# Fetch the artefacts of a specific commit without building
podman create --name fieldseal-dist ghcr.io/rezarajan/fieldseal/artifacts:sha-<commit> true
podman cp fieldseal-dist:/ ./dist && podman rm fieldseal-dist
```

`builder:latest` is convenient; `builder:<key>` from the CI log is exact. If your local `flake.lock` differs from the image's, `nix develop` downloads only the differences.
