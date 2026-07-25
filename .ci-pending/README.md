# CI workflow — pending a token with `workflow` scope

`ci.yml` in this directory is the intended GitHub Actions workflow for this repo.
It could not be pushed with the credential used for the initial release:

```
! [remote rejected] main -> main (refusing to allow an OAuth App to create or
  update workflow `.github/workflows/ci.yml` without `workflow` scope)
```

To install it, from a session whose token carries the `workflow` scope
(`gh auth refresh -s workflow`):

```bash
mkdir -p .github/workflows
git mv .ci-pending/ci.yml .github/workflows/ci.yml
git rm .ci-pending/README.md
git commit -m "ci: add GitHub Actions workflow"
git push
```

Then remove the CI badge caveat from `README.md` if you added one.

## What it runs

- `gofmt -l` — formatting check
- `go vet ./...`
- `go test -race ./...` on Go **1.23** (the declared minimum, which is a promise
  to consumers) and **stable**
- an assertion that `go.mod` has gained no `require` block

That last one is the important one. This module is embedded in other people's
binaries, so a dependency added here becomes a dependency everywhere. The
stdlib-only property is enforced in CI rather than left to reviewer discipline.

`make check` runs the same set locally.
