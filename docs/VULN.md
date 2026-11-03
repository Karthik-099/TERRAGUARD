# Vulnerability scanning

`terraguard vuln` checks dependency lockfiles and container images against an
offline copy of the [OSV](https://osv.dev) database. Only `vuln update` uses
the network; scans make no outside requests, so they work air-gapped once the
database is on disk.

## Download the database

```bash
terraguard vuln update                          # Go, npm, PyPI, Maven, RubyGems, crates.io,
                                                # Packagist, NuGet, Debian, Alpine, Ubuntu
terraguard vuln update --ecosystems npm,Go      # only what you use
terraguard vuln update --dir /srv/osv           # default: <user cache dir>/terraguard/osv
```

Each ecosystem is the public `all.zip` export from
`osv-vulnerabilities.storage.googleapis.com`, turned into a compact index. The
download is checked to be a valid zip, size-limited, and never executed. For an
air-gapped host, run `update` on a connected machine and copy the directory.
Run it again to refresh; a scan warns when the data is more than 7 days old.

Rough sizes on disk: npm 27 MB, Debian 47 MB, Alpine 26 MB, PyPI 5 MB, Go 3 MB.
npm takes about 25 seconds to fetch and index; the others a few seconds each.

## Scan a repository

```bash
terraguard vuln                       # current directory
terraguard vuln services/ --format sarif > vuln.sarif
terraguard vuln --fail-on CRITICAL --db /srv/osv
```

Lockfiles found (`node_modules`, `vendor` and hidden directories are skipped):

| Ecosystem | Files |
|---|---|
| Go | `go.mod` (or `go.sum` when there is no `go.mod`) |
| npm | `package-lock.json` (v1 to v3), `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5 to v9) |
| PyPI | `requirements*.txt` (exact `==` pins), `poetry.lock`, `Pipfile.lock` |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.lock` |
| NuGet | `packages.lock.json` |
| Maven | `gradle.lockfile` |

## Scan a container image

```bash
docker save IMAGE -o image.tar
terraguard vuln image image.tar
```

TerraGuard reads the archive itself (Docker `manifest.json` or an OCI layout
`index.json`, plain or gzip layers), applies the layers in order with
whiteouts, and reads `/etc/os-release`, `/var/lib/dpkg/status` (and
`status.d`), `/lib/apk/db/installed`, and the lockfiles above. OS packages are
matched as source packages against `Debian:<major>`, `Ubuntu:<version>` and
`Alpine:v<major.minor>`. It never runs Docker or anything in the image.

## Output and exit codes

`--format text|json|sarif|markdown`. Each finding names the package, installed
version, OSV ID and CVE aliases, severity, the fixed version when one exists,
and the lockfile line. Severity comes from the advisory's own rating, then its
CVSS v3 base score (9+ critical, 7+ high, 4+ medium, else low), else UNKNOWN.

Exit 0 when nothing is at or above `--fail-on` (default HIGH; `UNKNOWN` fails on
any finding, `NONE` never fails), 1 when something is, 2 on errors, including a
missing database or an ecosystem that was not downloaded.

## Limits

- Version ordering follows semver (npm, Go, crates.io), PEP 440 (PyPI, without
  local-version ordering), dpkg (Debian, Ubuntu) and apk (Alpine). Maven,
  RubyGems, NuGet and Packagist use a shared rule set for numbers and common
  pre-release words, not every qualifier each tool knows.
- `go.mod` `replace` directives are ignored, and the Go standard library and
  toolchain are not checked.
- Unpinned requirements (`>=`, `~=`) have no single installed version and are
  skipped.
- Images: Red Hat, Fedora and other rpm distributions are not matched; zstd
  layers are not supported; installed `node_modules` without a lockfile are not
  inventoried.
- Debian advisories with no fixed version are reported with "fixed: -", even
  when Debian rates them as minor or not affecting the built package.
