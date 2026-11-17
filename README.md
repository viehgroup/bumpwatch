# bumpwatch

Check dependency updates for hijacked releases before you merge them.

```
$ python examples/demo.py

llmkit 1.8.0 → 1.8.1 (pypi)
  high   BW003  New Python startup hook
    adds a .pth file that runs code at every Python start:
    import os, subprocess, sys;
    subprocess.Popen([sys.executable, '-c', 'import base64;
    exec(base64.b64decode("cHJpbnQoJ2J1b [wheel:llmkit_init.pth]
    fix: This is the technique used in both 2026 LiteLLM
         compromises. Don't install until you know why it's
         there.
  high   BW016  Wheel has files the source doesn't
    2 file(s) in the wheel aren't in the source distribution:
    llmkit/_telemetry.py, llmkit_init.pth [wheel]
    fix: Code that only exists in the built wheel can't be
         reviewed from source. That's how the LiteLLM implant
         hid.
  ... (7 more findings, including hidden code, credential
       theft, a raw IP endpoint and missing provenance)
```

<sub>`llmkit` is an inert recreation of the LiteLLM attack, served by a fake registry.</sub>

## Why

The worst supply-chain attacks of 2026 didn't use fake packages. They used real ones:

- **Axios** (npm, March): malicious versions 1.14.1 and 0.30.4 were published to one of the
  most-used packages on npm, then pulled.
- **LiteLLM** (PyPI, March and again in October): a `.pth` file in the wheel ran a
  credential stealer every time Python started. It wasn't in the project's source code.
- **Shai-Hulud** (npm, several waves): `postinstall` scripts stole npm and GitHub tokens,
  then used them to publish infected versions of the victims' own packages.

In every case, teams received an ordinary-looking pull request: *bump X from 1.2.3 to
1.2.4*. Somebody clicked merge.

bumpwatch downloads both versions from the official registry, compares them, and tells
you what the update **adds**: new install scripts, new startup hooks, hidden code,
credential access, a different publisher, missing build provenance. Behaviour that was
already there isn't reported again, so the signal stays clean.

## Quick start

```
pip install git+https://github.com/viehgroup/bumpwatch

bumpwatch check npm axios 1.14.0 1.14.1
bumpwatch inspect pypi litellm 1.109.1
bumpwatch diff old/package-lock.json package-lock.json
bumpwatch pr --base origin/main
```

`check` compares two versions, `inspect` compares a version with the release before it,
`diff` checks every change between two lockfiles, and `pr` checks every lockfile change
since a git ref.

No dependencies. npm and PyPI. Nothing is ever installed or executed: packages are read
in memory and checked against the registry's published checksums.

## GitHub Action

Runs on Dependabot and Renovate pull requests and puts the verdict where the merge
decision happens:

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  bumpwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: viehgroup/bumpwatch@main
        with:
          fail-on: high
```

Findings appear as annotations and in the job summary. With `comment: true` and
`pull-requests: write` permission it also posts a comment. (Dependabot pull requests get a
read-only token, so for those the job summary is where to look.) Pin the action to a
commit SHA in production workflows.

Lockfiles it reads: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `requirements*.txt` (`==` pins), `poetry.lock`, `uv.lock`,
`Pipfile.lock`. Files with other names are recognised by their content.

## What it checks

**Code that runs automatically**

| ID | Finding |
|---|---|
| BW001 | New npm install script (`preinstall`, `install`, `postinstall`, or an implicit `node-gyp` build) |
| BW002 | Install script changed |
| BW003 | New `.pth` line that executes code at every Python start |
| BW004 | New `sitecustomize.py` / `usercustomize.py` |
| BW005 | Install-time or startup code gains network or process calls |

**What new code does**

| ID | Finding |
|---|---|
| BW006 | Hidden code: `eval(atob(...))`, `exec(b64decode(...))`, `marshal`, obfuscator output, large encoded blobs |
| BW007 | Reads secrets and talks to the network in the same file |
| BW008 | New references to SSH keys, cloud credentials, registry tokens, wallets, browser data |
| BW009 | Raw IP addresses, exfiltration services, public IP lookups |
| BW010 | Persistence, reverse shells, `curl \| sh` |
| BW022 | Publishes packages or uses registry tokens, the way worms spread |
| BW023 | Reads GitHub Actions runtime tokens or writes workflow files |
| BW017 | First compiled binaries in a package that had none |
| BW020 | New process or network use (low; for context) |

**How it was published**

| ID | Finding |
|---|---|
| BW011 | Previous version had build provenance; this one doesn't |
| BW012 | Provenance names a different repository or workflow |
| BW013 | Published by an account that didn't publish recent releases |
| BW014 | Trusted publishing (CI via OIDC) was dropped |
| BW015 | Version doesn't exist, was pulled from the registry, or is yanked |
| BW016 | Code in the wheel that isn't in the source distribution |
| BW018 | New dependency that's days old, missing, or runs install scripts |
| BW019 | Released in the last few days (medium if anything else looks off) |
| BW021 | The package's source repository changed |

Run `bumpwatch rules` for full descriptions.

## Policy

Some packages legitimately run install scripts (`esbuild`, `sharp`). Put a
`.bumpwatch.json` in your repository:

```json
{
  "allow_install_scripts": ["esbuild", "sharp"],
  "ignore_rules": ["BW020"],
  "ignore_packages": ["@internal/tooling"],
  "fresh_days": 3
}
```

## How it was tested

- **Real hijack.** `bumpwatch inspect npm axios 1.14.1` finds the version before it and
  reports that 1.14.1 was published and then pulled. CI runs this against the live
  registry on every push.
- **Real updates.** The latest update of 37 popular packages (React, Next.js, TypeScript,
  esbuild, sharp, Vite, ESLint, the Anthropic and OpenAI SDKs, requests, NumPy, Django,
  FastAPI, pandas, cryptography, setuptools, pytest-cov, LiteLLM and more): no high
  findings. Two mediums, both accurate: TypeScript 7 was published from a different
  npm account, and axios 1.13.3 was published without the provenance 1.13.2 had.
- **Attack recreations.** Inert rebuilds of the Shai-Hulud worm, the LiteLLM `.pth`
  implant and an Axios-style malicious dependency are each caught on every behaviour.
  See `examples/demo.py`.
- **Real lockfiles** produced by `npm` and `uv`, including the pull-request flow through
  git and a shallow clone like GitHub's default checkout.
- 21 unit tests on Python 3.9, 3.11 and 3.13.

```
python -m unittest discover -s . -p "test_*.py" -v
```

## Limits

- It reads code; it doesn't run it. A determined attacker can try to hide from pattern
  matching. Provenance and publisher checks are harder to fake.
- Provenance is read from the registry's metadata, not cryptographically verified. For
  signature checks use `npm audit signatures` or `pypi-attestations`.
- For Python it compares one wheel (pure-Python, else manylinux x86_64) plus the sdist,
  not every platform's wheel.
- It checks direct changes in lockfiles, up to 60 per run by default (`--max`).
- A clean result means nothing suspicious changed, not that a package is safe.

## Related

From the same team:
[slopwatch](https://github.com/viehgroup/slopwatch) blocks hallucinated and typosquatted
packages, [agentscan](https://github.com/viehgroup/agentscan) finds leaked keys and risky
settings in AI agent configs, and [extwatch](https://github.com/viehgroup/extwatch)
catches backdoored editor extensions.

## License

MIT. Built and maintained by the **VIEH Security Team**.
