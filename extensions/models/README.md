# @sntxrr/traefik

Keep Traefik reverse proxies, the images beside them (CrowdSec, …) and every
plugin they load up to date, through pull requests to the repository each proxy
is deployed from. It never touches a running proxy.

One model instance describes one deployment: the host Traefik runs on, and the
GitHub repository its compose file and static configuration live in.

| method    | writes                  | what it does |
| --------- | ----------------------- | ------------ |
| `inspect` | nothing                 | Live state: running version, start time, HTTP/TCP/UDP router and middleware status, whether plugins failed to load since this start. |
| `check`   | nothing                 | Repository pins vs running vs upstream for Traefik, tracked images and every plugin. Reports findings: what is behind, remote plugins, undeployed pins, a published insecure API, disabled routers or plugin middlewares, and anything it could not determine. |
| `bump`    | a pull request (opt-in) | One PR per component that is behind: an image tag, a remote plugin's version, or a re-vendored local plugin. **Dry-run by default.** |

## Why plugins get special treatment

A plugin declared under `experimental.plugins` is **downloaded from the plugin
catalog on every start**. If that download fails (a timeout is enough), Traefik
disables _all_ plugins. Every router that references a plugin middleware is then
disabled too, and an entrypoint-level middleware such as a CrowdSec bouncer is
referenced by every router. Traefik keeps running and keeps serving its
certificate while every site returns 404.

So:

- `check` reports every remote plugin as a `remote-plugin` finding.
- `bump` refuses an instance with remote plugins unless you pass
  `allowRemotePlugins: true`. Each merged bump restarts Traefik, and each
  restart risks that download failing.
- The fix is to vendor the plugin into the repository and load it through
  `experimental.localPlugins` from a read-only `/plugins-local` mount. `bump`
  keeps vendored plugins current:
  - It downloads the new tag and copies the runtime files: Go sources,
    `vendor/`, `.traefik.yml`, `go.mod`/`go.sum`, licences, and every file the
    previous copy had (templates and other assets in subdirectories included).
    Tests, examples and CI files are left out.
  - It resolves the tag to its commit once, downloads that commit's source
    archive (so a tag moved in between cannot mix two commits), and records
    the commit and the archive's sha256 in the vendoring record.
  - A tarball that needs extended headers for long paths is refused rather
    than extracted with files missing.
  - Files that did not change are not rewritten. Files the new tag no longer
    has are removed. New files it did not copy are listed in the PR for a
    reviewer.
  - The record is edited only inside the bumped plugin's own section, so a
    record that lists two plugins at the same version never has the other one
    rewritten. If that section does not mention the old version, `bump` refuses
    rather than ship code whose record still names the old one.
  - A `.traefik.yml` catalog test value that looks like a key gets
    `# gitleaks:allow`, keeping any annotation the previous copy had.

## What leaves the host

`inspect` and `check` run one fixed script over SSH. It contains only read-only
`docker` subcommands, and nothing caller-supplied is interpolated except a
validated container name, port and path:

- `docker inspect` with four named fields (image, state, start time, restart
  count). The environment is never read.
- `docker exec <c> traefik version`.
- `docker exec <c> wget` against the API on loopback, when `apiUrl` is not set
  or not reachable.
- `docker logs`, and `test`/`grep` on the log file, for the plugin-failure
  marker.

API documents are rebuilt from named fields only: name, status, type, provider,
error. A plugin middleware's configuration, which can hold a LAPI key, is never
read into a resource. Its error text is withheld too, because plugin
constructors often echo their configuration in errors. A failed or partial API
read is described ("partial or invalid JSON response"), never quoted.

## Unknown is never "current"

- `healthy` is `true` only when everything was checked. It is `false` when
  anything failed, including a disabled plugin middleware or a TCP/UDP router.
  It is `null` when the API (router and middleware health) or the
  plugin-failure log could not be read.
- If the API is unreachable, there is an `api-unreachable` warning.
- A version that cannot be compared is a `version-unknown` warning, with the
  reason: a floating tag such as `v3`, an unparseable pin, or no upstream
  release in the pinned major.
- An image built from variables (`${IMAGE}`) is an `image-unresolved` finding.
- The static configuration is found the way Traefik finds it (see
  [Configuration supported](#configuration-supported)). When it cannot be
  determined, there is a `static-config-unknown` warning, plugins are not
  checked, and `bump` refuses as it does for remote plugins: unknown is not
  "no plugins".
- If `docker logs` cannot be read (a logging driver without read support) and
  no log file is readable, there is a `container-logs-unreadable` warning. A
  configured log file that cannot be read is `log-file-unreadable`. A relative
  `log.filePath` is resolved against `/`, Traefik's working directory.
- Only Traefik's own log record counts as a plugin failure (v3 text, coloured
  or not, v2 text, or JSON), never a line that merely contains the phrase: an
  access log on the same stream can carry it in any request.
- A log file outlives restarts. A plugin failure counts only if its timestamp is
  after the container started, and a record whose timestamp cannot be parsed
  counts.
- A TCP or UDP router list that is absent (404 on an older Traefik) is skipped;
  one that fails to read in any other way leaves router health unchecked.
- An exhausted GitHub rate limit, or a registry answering anything but 200/404,
  throws.
- A release whose image is not yet pushed is reported with
  `imageAvailable: false` and is not bumped.

## Dependabot

A component that already has an open PR moving it to the target (or past it) is
reported with that PR, and `bump` does not open a second one. Only PRs into
`ref` from the deployment repository's own branches count, and a
`Bump x from a to b` title counts only from Dependabot or Renovate, and only
when `a` is the current pin. An open PR that
stops short of the newest release (say, Dependabot proposing `v3.7.15` when
`v3.7.16` is out) is named in the new PR as superseded. `bump`'s own branches
(`swamp-traefik/<component>-<version>`) are matched exactly.

## Upgrade policy

A bump changes exactly one thing:

- An image edit retags only the lines that carry the compared pin. Another
  service on the same image at another tag is reported (`mixed-pins`) and left
  alone.
- A variant suffix is kept: `v1.6.3-debian` becomes `v1.6.4-debian`, never
  `v1.6.4`.
- The PR is built on the commit the plan was read from, so a commit that lands
  on the branch meanwhile is never reverted.
- An explicit `toVersion` must be a real upstream release, and an image's new
  tag must exist in its registry.
- A branch left by a closed PR or an interrupted run is reported, not
  overwritten.
- Each component is independent. One failing is recorded with its error, the
  rest still run, and the method fails at the end, after recording every PR it
  did open.

A plugin still on 0.x gets minor updates like any other (staying current is
the point), but the PR says that under semver a 0.x minor may break
compatibility.

The target is the newest stable release **in the pinned major**. Plugins are
compared against git tags as well as releases, since Traefik's plugin catalog
serves tags. A newer major
is reported as a `newer-major` finding and is only bumped when you pass both
`toVersion` and `allowMajor: true`. Prereleases are never offered unless
`allowPrerelease` is set.

Upstream releases are read anonymously, and reading stops once it reaches the
pinned version. That costs a few requests per instance, well within GitHub's
anonymous limit of 60 requests/hour per IP. If something else on the same IP
exhausts that limit, set `upstreamToken`: a token with no scopes, used only for
public upstream reads and never for the deployment repository. Upstream reads
always go to `https://api.github.com`, whatever `githubApiUrl` says, and
`githubApiUrl` must be https.

## Example

```yaml
type: "@sntxrr/traefik/instance"
name: edge-proxy
globalArguments:
  sshHost: proxy.example.net
  sshUser: deploy
  container: traefik
  repo: example/edge-proxy
  composeFiles: [docker-compose.yml]
  staticConfig: traefik.toml
  # A token for THIS repository only (contents + pull requests). Never sent to
  # upstream projects; their releases are read anonymously.
  githubToken: "${{ env.GH_TOKEN }}"
```

```bash
swamp behavior run edge-proxy check
swamp behavior run edge-proxy bump                         # dry-run: the exact edits
swamp behavior run edge-proxy bump --input dryRun=false    # open the PRs
swamp behavior run edge-proxy bump --input component=plugin:my-plugin --input toVersion=v1.8.1
```

## Configuration supported

The static configuration is located the way Traefik locates it. Traefik reads
the first file that exists among the `--configFile` value,
`/etc/traefik/traefik.*`, `$XDG_CONFIG_HOME/traefik.*`,
`$HOME/.config/traefik.*` and `./traefik.*`, and ignores every CLI flag when
it finds one. The model walks those paths through the Traefik service's
compose volumes:

- a bind mount from the repository resolves to the repository file;
- a mount the repository does not describe (an absolute host path, a named
  volume) makes the source unknown, unless `staticConfig` names the file;
- with no file found, CLI flags in the compose `command:` configure it;
- with neither, Traefik runs on defaults, unless `TRAEFIK_*` environment
  variables might configure it, which is reported as unknown.

Also:

- `staticConfig` naming a file Traefik does not read is reported
  (`static-config-shadowed`, or `static-config-mismatch` when another file is
  read), and flags ignored because a file wins are `static-flags-ignored`;
- keys in a static file match case-insensitively, as Traefik decodes them;
- a remote plugin bump edits only the source Traefik reads, and re-reads the
  edited text to confirm exactly that plugin's version moved;
- image references with or without a registry, `library/`, a digest or a
  variant suffix;
- several compose files, for example Traefik and CrowdSec in separate ones.

## Using it from a workflow

`check` writes a `check` resource with `behind`, `critical`, `findingCount` and
a ready-to-send `summary`. Gate a notification on
`data.latest('<instance>', 'check').attributes.behind` or `.critical`. Do not
gate on `runtime.healthy == true`: `null` means "not fully checked".

## Development

```bash
~/.swamp/deno/deno check extensions/models/traefik.ts
~/.swamp/deno/deno lint extensions/models/
~/.swamp/deno/deno test extensions/models/
```
