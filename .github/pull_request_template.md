<!-- What this PR changes and why. -->

## Threat-model change: re-sign the exec manifest

A client that verifies signatures loads a changed `threatmodel-*.json` only
when `signed/manifest-exec.json` lists it and a root key signed that manifest.
The `regen` check fails until then. Data files (`*-db.json`, `consent/*`) need
nothing here: `sign_manifests.yml` signs them after the merge.

- [ ] This PR changes no `threatmodel-*.json` (nothing else to do), or:
- [ ] The branch is rebased on `main`, the `make update` output is committed,
      and the other checks are green.
- [ ] In a clean checkout of this branch, the exec manifest is built, signed
      with root key A and verified:

  ```sh
  python3 src/publish/sign-manifest.py build --scope exec
  python3 src/publish/sign-manifest.py sign --scope exec --key "$ROOT_A_PEM"
  python3 src/publish/sign-manifest.py verify --scope exec --branch main --public-key 5b5d49de669207ebf90a8d4cb07a69c61f425515be8e69cef6aec83872fc59c4 --public-key e1fcfd06a9baafc2f4c9cd5ba5d2b8721c1e7e4df5adbb027549f8ff740319cb
  ```

  `ROOT_A_PEM` is the path of root key A's private key file (RECORD.md). The
  two public keys are root A (key id `93295ebcb9a6ec08`) and root B (key id
  `39f35c44b16e9f62`). `verify` must end with
  `signed by 93295ebcb9a6ec08 (root)`.
- [ ] `signed/manifest-exec.json` and `signed/manifest-exec.sig.json` are
      committed to this PR.
- [ ] No other threat-model change merged into `main` since the signature
      (otherwise rebase and sign again).
