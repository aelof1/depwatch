# depwatch

Vulnerable dependency scanner for **Python** and **Node.js** projects. It reads `requirements.txt`, `package.json` or `package-lock.json` and lists the known vulnerabilities (CVE) of each library, with the version that fixes them.

The data comes from [OSV.dev](https://osv.dev), the open source vulnerability database maintained by Google. It is **free and needs no API key**.

## Why I built this

Most vulnerabilities in an application don't come from the code we write, but from the libraries we install (Log4Shell is the best-known example). Tools like `npm audit`, `pip-audit` or Dependabot exist; I wanted to understand how they work by querying a vulnerability API myself, and to have a single tool for both Python and npm.

## Supported files

| File | Ecosystem | Note |
|---|---|---|
| `requirements.txt` (and `requirements-dev.txt`…) | Python / PyPI | only exact versions (`==`) are checked |
| `package-lock.json` | Node.js / npm | the most accurate: every dependency, even indirect ones |
| `package.json` | Node.js / npm | only used when there is no `package-lock.json` |

If you give a folder, the tool looks for these files in all its subfolders (except `node_modules` and `.venv`).

## Compatibility

| System | Works? |
|---|---|
| Linux (all distributions) | Yes |
| macOS | Yes |
| Windows 10 / 11 | Yes |

## Requirements

- **Python 3.9 or newer**
- **An Internet connection** (HTTPS access to `api.osv.dev`)
- No external Python libraries, no API key
- A corporate proxy is supported through the `HTTPS_PROXY` variable.

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git
git clone https://github.com/aelof1/depwatch.git
cd depwatch
pipx install .
```

### Fedora

```bash
sudo dnf install -y python3 pipx git
```

### macOS

```bash
brew install python pipx git
```

### Windows

Install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH"), then in the project folder: `pip install .`

## Usage

```bash
depwatch                          # project in the current folder
depwatch ~/projects/my-site       # another folder
depwatch requirements.txt         # a single file
depwatch samples                  # included examples (old vulnerable versions)
depwatch . --json                 # JSON, handy in CI
```

Exit code: `0` if there are no vulnerabilities, `1` otherwise, `2` if the API can't be reached.

### Example output (shortened)

```
Files: samples/package.json, samples/requirements.txt
Dependencies checked: 9

[CRITICAL] django 3.2.0  GHSA-xpfp-f569-q3p2 (CVE-2021-35042)
           Potential SQL injection via unsanitized QuerySet.order_by() input
           -> upgrade to 3.2.5   https://osv.dev/vulnerability/GHSA-xpfp-f569-q3p2
[HIGH    ] lodash 4.17.15  GHSA-35jh-r3h4-6jhm (CVE-2021-23337)
           Command Injection in lodash
           -> upgrade to 4.17.21   https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
...
Note: 2 dependencies without an exact version were skipped: flask>=2.0, axios@latest
Pin versions (pip freeze > requirements.txt) or use a lockfile for a complete scan.
```

### Preparing your project

- **Python**: `pip freeze > requirements.txt` gives the exact installed versions.
- **Node.js**: run `npm install` to generate `package-lock.json`, and commit it.

## How it works

1. Read the dependency files, which gives a list of "name + version".
2. Send a single batched `POST /v1/querybatch` request to OSV for every package.
3. For each vulnerability found, `GET /v1/vulns/<id>` fetches the summary, severity, CVE number and fixed version. Responses are cached so the same thing is never asked twice.

## Project layout

```
depwatch/
├── depwatch/
│   ├── parsers.py   # reading dependency files
│   ├── osv.py       # OSV API client
│   └── cli.py
├── samples/         # deliberately vulnerable example project
└── tests/           # the tests fake the API (no Internet needed)
```

## Tests

```bash
pip install pytest
python3 -m pytest
```

## Limitations

- Dependencies without an exact version (`flask>=2.0`, `"axios": "latest"`) are not checked: there's no way to know which version is really installed.
- No support yet for `poetry.lock`, `Pipfile.lock`, `yarn.lock`, `pom.xml`…
- Some advisories only have a CVSS vector: the severity is then shown as `CVSS`. Open the link for details.

## Ideas for later

- Support for `poetry.lock`, `yarn.lock` and `go.sum`
- `--fail-on high` option to only fail CI on serious vulnerabilities
- HTML report

## License

MIT
