# GitHub Action

Probe hosts from a workflow, keep the JSON reports, show a summary table on the run page, and
optionally fail the job when a host does not complete a post-quantum key exchange.

## Report only

```yaml
jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - id: pqc
        uses: asifmahbubnaeem/pqc-probe@v0.2.0
        with:
          targets: |
            example.com
            git.example.com:2222
          protocol: both
      - uses: actions/upload-artifact@v4
        with:
          name: pqc-reports
          path: ${{ steps.pqc.outputs.report-dir }}
```

## As a gate

```yaml
      - uses: asifmahbubnaeem/pqc-probe@v0.2.0
        with:
          targets: api.example.com, www.example.com
          protocol: tls
          require-pq-tls: "true"
```

The job fails if any target does not complete a TLS handshake with a post-quantum group.
Each failure is also an annotation on the run.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `targets` | (required) | `host` or `host:port`, separated by spaces, commas or new lines; `#` starts a comment |
| `protocol` | `both` | `tls`, `ssh` or `both` |
| `mode` | `both` | `vanilla` (stock clients), `experimental` (OQS clients), `both` (compared) |
| `tls-port` / `ssh-port` | | port for every target (defaults 443 / 22) |
| `timeout` | `15` | seconds per connection attempt (1-120) |
| `require-pq-tls` | `false` | fail if a target completes no TLS handshake with a post-quantum group |
| `require-pq-ssh` | `false` | fail if a target completes no SSH key exchange with a post-quantum algorithm |
| `fail-on-error` | `true` | fail if a target could not be probed at all |
| `output-dir` | `pqc-probe-reports` | where the JSON reports go (one file per target) |
| `image` | | image to run instead of the default |

Outputs: `report-dir`, `violations` (targets that broke a policy), `errors` (targets that could
not be probed).

## What counts as post-quantum

A handshake must have **completed** with the group or key exchange; being offered is not
enough. Names that count: anything containing `mlkem`, `kyber`, `frodo`, `bike`, `hqc` or
`sntrup` (the same rule as the tool itself). Either client stack may complete it: a TLS
handshake with `X25519MLKEM768` by the stock OpenSSL 3.5 counts.

The reports follow the public JSON schema in `schema/report-v1.json`, so later steps can apply
stricter rules with `jq`.

## Which image runs

The action runs the pqc-probe Docker image, which carries both client stacks
(see `docs/docker.md`):

- referenced by a version tag (`@v0.1.0`, `@v0.1`, `@v0`): the image with the same version from
  `ghcr.io/asifmahbubnaeem/pqc-probe`
- referenced by a branch or commit: the `edge` image
- `image:` input: exactly that image

## Be polite

Each target costs a few connections per protocol (TLS: one per group tried; SSH: one to read
the offer plus up to 8 paced handshakes). Probe your own hosts, and avoid running the gate on
every push against third-party servers.

## Maintainers

- `.github/workflows/image.yml` publishes the image: on a `v*.*.*` tag (version tags and
  `latest`) and when run by hand on `main` (`edge`). After the first publish, set the package's
  visibility to public in its GitHub settings, or workflows in other repositories cannot pull it.
- `action/test.sh` tests the action's logic with a fake `docker` and canned reports; CI runs it.
- CI also runs ShellCheck on the action's scripts.
- `.github/workflows/action-e2e.yml` builds the image and runs the action against github.com.
