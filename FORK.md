# This fork

An independent build of [OpenObserve](https://github.com/openobserve/openobserve) that follows upstream `main` and adds its own features. It keeps the upstream AGPL-3.0 license and notices.

## Branches

- `main` is the fork: upstream `main` plus this fork's features and CI.
- Features land on `main` through pull requests. Each feature documents itself (for example `docs/oidc`).
- Merge pull requests into `main` with a merge commit, never squash or rebase, so upstream history stays intact and each sync merges only new upstream commits.

## CI

Upstream workflows need runners only upstream has, so `upstream-sync.yml` disables every workflow outside its `KEEP` list, including ones a sync brings in. Of upstream's workflows only `gitleaks` is kept; to run another, add its file name to `KEEP` and `gh workflow enable` it.

| Workflow | Runs | Does |
| --- | --- | --- |
| `fork-ci.yml` | Every pull request and push to `main`, for the areas the change touches | Rust fmt, clippy and the workspace tests; web format, lint, unit tests and Cypress specs |
| `upstream-sync.yml` | Mondays 03:17 UTC, on demand, and on push to `main` | Merges upstream `main` into the `sync/upstream` pull request (not on push), and disables workflows outside `KEEP` |
| `fork-release.yml` | Every pushed `v*` tag | Builds `deploy/build/Dockerfile` and pushes it to `ghcr.io/<owner>/openobserve` |

## Upstream sync

One-time setup: create a fine-grained personal access token for this repository only, with read and write access to Contents, Pull requests and Workflows, and store it as the Actions secret `SYNC_TOKEN`. The default `GITHUB_TOKEN` cannot push upstream's workflow changes, and pull requests it opens do not start CI.

Each run opens or updates the `sync/upstream` pull request. Review it like any other: Fork CI must pass, and check upstream changes to the places your features hook into. Run it now with:

```sh
gh workflow run upstream-sync.yml
```

A conflict fails the run, and its summary lists the files. Resolve it locally and push the branch; the next run updates the same pull request:

```sh
git fetch origin && git fetch upstream main
git switch -C sync/upstream origin/main   # or origin/sync/upstream while its PR is open
git merge upstream/main                   # resolve, test, commit
git push origin sync/upstream
gh pr create --base main --head sync/upstream --fill   # only if no sync PR is open
```

## Releases

Tag a commit on `main` that passed Fork CI, then push the tag:

```sh
git tag -a v2026.11.23 -m "Release 2026.11.23" origin/main
git push origin v2026.11.23
```

The image is published as `ghcr.io/<owner>/openobserve:<tag>` and `:latest`. Upstream's versions keep advancing on `main`, so the tag is this fork's own version; a date works well. After the first release, check the package's visibility in its settings. Back up the metadata database before deploying a new image.
