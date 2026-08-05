# vyprai/homebrew-tap

Homebrew formulae for [VyQL](https://github.com/vyprai/vyql), a multi-language
taint and graph security scanner.

```sh
brew install vyprai/tap/vyql
vyql scan .
```

`scan` exits 1 when it finds anything HIGH or CRITICAL, so it gates a pipeline
with no further configuration. `vyql scan -fail-on none .` reports without
gating.

## What the formula installs

VyQL reads its security knowledge from a `vyql/` directory at run time and finds
it by walking up from the resolved path of its own executable. The formula keeps
the binary and that directory together under `libexec`, and `bin/vyql` is a
symlink into it.

This needs VyQL 0.2.1 or later. Earlier versions read the symlink's own path on
macOS rather than following it, so a Homebrew install could not find its data
and exited with `could not locate the data directory`.

## Other ways to install

```sh
curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh   # no Homebrew
docker run --rm -v "$PWD:/work" ghcr.io/vyprai/vyql scan .
go install github.com/vyprai/vyql/cmd/vyql@latest       # needs a C toolchain
```
