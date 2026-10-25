/**
 * Traefik — keep a fleet of Traefik reverse proxies, and every plugin they
 * load, current, without ever touching a running proxy.
 *
 * One model instance describes one Traefik deployment: the host it runs on,
 * and the git repository its configuration is deployed from. Three methods:
 *
 * - **`inspect`** (read-only, live). What the proxy is actually doing: the
 *   running version, when it started, whether its plugins loaded, and the
 *   status of every HTTP, TCP and UDP router and every middleware. Reads the
 *   Traefik API directly when `apiUrl` is reachable, and otherwise over SSH
 *   from inside the container.
 *
 * - **`check`** (read-only). Compares three things: what the repository pins
 *   (the Traefik image, any tracked sidecar images such as CrowdSec, and every
 *   plugin's version), what is running, and what upstream has released. It
 *   reports what is behind and also how the deployment is exposed:
 *   - a plugin that Traefik downloads at startup,
 *   - a pin that never reached the host,
 *   - an insecure API published on a host port,
 *   - routers or plugin middlewares disabled right now,
 *   - anything it could not determine.
 *
 * - **`bump`** (writes a pull request, dry-run by default). Opens one PR per
 *   component in the deployment's repository:
 *   - an image tag edit,
 *   - a remote plugin's version edit,
 *   - or, for a vendored local plugin, a re-vendor of the new upstream tag
 *     with its provenance recorded.
 *   It never merges, and never contacts the host. The repository's own CI and
 *   deploy job roll the change out and verify it. That is the only path to
 *   production.
 *
 * Design choices worth knowing before changing anything:
 *
 * - **Plugins are first-class, and remote plugins are a finding.** A plugin
 *   loaded through `experimental.plugins` is downloaded from the plugin catalog
 *   on *every* start. If that download fails, Traefik disables every plugin.
 *   Any router that references a plugin middleware (an entrypoint-level
 *   CrowdSec bouncer references them all) is then disabled, and every site
 *   returns 404 while Traefik itself keeps running. `bump` therefore refuses an
 *   instance with remote plugins unless the caller sets `allowRemotePlugins`:
 *   every bump merge is a restart, and every restart re-rolls that dice.
 *   Vendoring the plugin into `experimental.localPlugins` removes the risk.
 *
 * - **Nothing secret leaves the host.** Plugin middlewares carry their
 *   configuration in the API response, and a CrowdSec bouncer's LAPI key can be
 *   in it. Every API document is rebuilt from named fields (name, status, type,
 *   provider, error), a plugin middleware's error text is withheld because it
 *   can echo that configuration, and raw API output is never quoted in an
 *   error. `docker inspect` is asked for four named fields, never the
 *   environment.
 *
 * - **Unknown is never "current".** `healthy` is null, not true, while router
 *   health or the plugin-failure log could not be read. A version that cannot
 *   be compared (a floating tag, an unparseable pin, no upstream release in the
 *   pinned major) is a `version-unknown` finding. A rate-limited release list
 *   or a registry that answers neither 200 nor 404 throws. Empty SSH output
 *   throws.
 *
 * - **A bump changes exactly one thing.** An image edit retags only lines that
 *   carry the compared pin, so a second service on another major is left alone.
 *   A tag's variant suffix (`-debian`, `-alpine`) is kept. A vendored plugin's
 *   record is edited only inside that plugin's own section. The PR is built on
 *   the commit the plan was read from, so a commit landing meanwhile is never
 *   reverted.
 *
 * - **Dependabot is respected.** A component that already has an open PR
 *   bumping it to the target (or further) is reported with that PR, and `bump`
 *   does not open a second one. One that stops short is named as superseded.
 */
import { z } from "npm:zod@4";
import { parse as parseToml } from "jsr:@std/toml@1.0.11";
import { parse as parseYaml } from "jsr:@std/yaml@1.3.0";
import { UntarStream } from "jsr:@std/tar@0.1.10/untar-stream";

// ---------------------------------------------------------------------------
// Versions and tags
// ---------------------------------------------------------------------------

/** A parsed semantic version. `prerelease` is null for a final release. */
export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
}

/** A pinned tag: its version, how precise it is, and any variant suffix. */
export interface PinnedTag {
  version: ParsedVersion;
  /** `v` when the tag is written with a leading v. */
  prefix: "v" | "";
  /** How many numeric parts were written: `v3` is 1, `v3.7` is 2. */
  precision: 1 | 2 | 3;
  /** A build variant such as `-debian` or `-alpine`; never compared. */
  variant: string;
}

/**
 * Parse a tag such as `v3.7.16`, `3.7`, `v1.8.1-rc.1` or `v1.6.3-debian`.
 *
 * A suffix is a *prerelease* only when it starts with rc/alpha/beta/pre/
 * preview/dev/next/canary/nightly/snapshot/milestone or is purely numeric; any other suffix (`-debian`, `-alpine`,
 * `-windowsservercore`) is a *variant* of the same release. Reading a variant
 * as a prerelease would make every variant pin look older than its own release
 * and propose a "patch" that switches the base image.
 */
export function parseTag(raw: string): PinnedTag | null {
  const m = raw.trim().split("+")[0].match(
    /^(v?)(\d+)(?:\.(\d+))?(?:\.(\d+))?(-(?:(?:rc|alpha|beta|pre|preview|dev|next|canary|nightly|snapshot|milestone|m)\.?\d*(?:\.\d+)*|\d+(?:\.\d+)*))?(-[A-Za-z][0-9A-Za-z._-]*)?$/i,
  );
  if (!m) return null;
  return {
    version: {
      major: parseInt(m[2], 10),
      minor: m[3] ? parseInt(m[3], 10) : 0,
      patch: m[4] ? parseInt(m[4], 10) : 0,
      prerelease: m[5] ? m[5].slice(1) : null,
    },
    prefix: m[1] ? "v" : "",
    precision: m[4] !== undefined ? 3 : m[3] !== undefined ? 2 : 1,
    variant: m[6] ?? "",
  };
}

/**
 * Parse a version, ignoring any variant suffix. Returns null for anything
 * that is not a version, including `latest` and digests.
 */
export function parseVersion(raw: string): ParsedVersion | null {
  return parseTag(raw)?.version ?? null;
}

/** Semver precedence: a prerelease sorts below the release it precedes. */
export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.prerelease === null && b.prerelease === null) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  // Semver: dot-separated identifiers, numeric ones compared as numbers, so
  // rc.10 sorts after rc.9 (a plain string compare gets that backwards).
  const pa = a.prerelease.split(/[.-]/);
  const pb = b.prerelease.split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === undefined) return -1;
    if (pb[i] === undefined) return 1;
    const na = /^\d+$/.test(pa[i]) ? parseInt(pa[i], 10) : null;
    const nb = /^\d+$/.test(pb[i]) ? parseInt(pb[i], 10) : null;
    if (na !== null && nb !== null) {
      if (na !== nb) return na - nb;
    } else if (na !== null) return -1;
    else if (nb !== null) return 1;
    else if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/** Which part of the version a move from `a` to `b` changes. */
export function bumpKind(
  a: ParsedVersion,
  b: ParsedVersion,
): "major" | "minor" | "patch" {
  if (a.major !== b.major) return "major";
  if (a.minor !== b.minor) return "minor";
  return "patch";
}

/**
 * Render `target` the way the pin is written: keep or drop the leading `v`,
 * and keep the pin's variant suffix. `traefik:v3.7.9` becomes `v3.7.16`;
 * `crowdsec:v1.6.3-debian` becomes `v1.6.4-debian`.
 */
export function formatLike(pinned: string, target: string): string {
  const pin = parseTag(pinned);
  const t = parseTag(target);
  if (!t) return target;
  const v = t.version;
  const core = `${v.major}.${v.minor}.${v.patch}${
    v.prerelease ? `-${v.prerelease}` : ""
  }`;
  const prefix = pin ? pin.prefix : /^v/i.test(pinned.trim()) ? "v" : "";
  return `${prefix}${core}${pin?.variant ?? ""}`;
}

// ---------------------------------------------------------------------------
// Image references
// ---------------------------------------------------------------------------

/** An image reference split into the parts that matter here. */
export interface ImageRef {
  /** As written, e.g. `docker.io/library/traefik:v3.7.9`. */
  raw: string;
  /** Registry host, `docker.io` when unqualified. */
  registry: string;
  /** Normalised short repository: `traefik`, `crowdsecurity/crowdsec`. */
  repository: string;
  tag: string | null;
  digest: string | null;
}

/**
 * Parse an image reference. Docker Hub's `library/` namespace and the
 * `docker.io` / `index.docker.io` / `registry-1.docker.io` hosts are folded
 * away, so `traefik`, `library/traefik` and `docker.io/library/traefik` all
 * normalise to `traefik`. A reference built from variables (`${IMAGE}`)
 * returns null: it cannot be compared.
 */
export function parseImageRef(raw: string): ImageRef | null {
  const ref = raw.trim().replace(/^['"]|['"]$/g, "");
  if (!ref || /\s/.test(ref) || ref.includes("$")) return null;
  let rest = ref;
  let digest: string | null = null;
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let tag: string | null = null;
  const lastSlash = rest.lastIndexOf("/");
  const colon = rest.lastIndexOf(":");
  if (colon > lastSlash) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  let registry = "docker.io";
  const first = rest.split("/")[0];
  if (
    rest.includes("/") &&
    (first.includes(".") || first.includes(":") || first === "localhost")
  ) {
    registry = first;
    rest = rest.slice(first.length + 1);
  }
  if (["index.docker.io", "registry-1.docker.io"].includes(registry)) {
    registry = "docker.io";
  }
  if (registry === "docker.io") rest = rest.replace(/^library\//, "");
  if (!rest) return null;
  return { raw: ref, registry, repository: rest, tag, digest };
}

/** True when an image reference is Traefik itself. */
export function isTraefikImage(ref: ImageRef): boolean {
  return ref.repository === "traefik" ||
    (ref.registry !== "docker.io" && /(^|\/)traefik$/.test(ref.repository));
}

/** Where to verify an image tag exists: registry host + full repository path. */
export function registryCoordinates(
  ref: ImageRef,
): { host: string; repository: string } {
  if (ref.registry === "docker.io") {
    return {
      host: "registry-1.docker.io",
      repository: ref.repository.includes("/")
        ? ref.repository
        : `library/${ref.repository}`,
    };
  }
  return { host: ref.registry, repository: ref.repository };
}

// ---------------------------------------------------------------------------
// Repository configuration
// ---------------------------------------------------------------------------

/** A plugin as the static configuration declares it. */
export interface PluginDecl {
  /** The key under `experimental.plugins` / `experimental.localPlugins`. */
  name: string;
  moduleName: string;
  /** Pinned version. Null for a local plugin; see the vendoring record. */
  version: string | null;
  /** `remote` downloads at startup, `local` loads from /plugins-local. */
  mode: "remote" | "local";
  /** Where the declaration lives. */
  source: "cli" | "file";
}

/** An image line in a compose file. */
export interface ComposeImage {
  file: string;
  service: string;
  ref: ImageRef;
}

/** An `image:` that could not be parsed, usually because it uses variables. */
export interface UnresolvedImage {
  file: string;
  service: string;
  raw: string;
}

/** Static settings this model reasons about, from CLI args or a file. */
export interface StaticSettings {
  apiInsecure: boolean;
  /** `log.filePath`, when the proxy logs to a file instead of stdout. */
  logFilePath: string | null;
  /** The `traefik` entrypoint's port, which serves the insecure API. */
  apiEntrypointPort: number;
  plugins: PluginDecl[];
}

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : {};
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : typeof v === "number" ? String(v) : null;
}

function unquote(s: string): string {
  return s.trim().replace(/^(['"])(.*)\1$/, "$2");
}

/** Parse a compose document. Throws with the file name on invalid YAML. */
export function parseCompose(
  file: string,
  text: string,
): Record<string, unknown> {
  try {
    return asRecord(parseYaml(text));
  } catch (err) {
    throw new Error(
      `${file} is not valid YAML: ${err instanceof Error ? err.message : err}`,
    );
  }
}

/** Every service's `image:`, parsed or (when it uses variables) not. */
export function composeImages(
  file: string,
  doc: Record<string, unknown>,
): { images: ComposeImage[]; unresolved: UnresolvedImage[] } {
  const images: ComposeImage[] = [];
  const unresolved: UnresolvedImage[] = [];
  for (const [service, def] of Object.entries(asRecord(doc.services))) {
    const raw = asString(asRecord(def).image);
    if (!raw) continue;
    const ref = parseImageRef(raw);
    if (ref) images.push({ file, service, ref });
    else unresolved.push({ file, service, raw });
  }
  return { images, unresolved };
}

/** A compose service's `command`, as a list of arguments. */
export function serviceCommand(
  doc: Record<string, unknown>,
  service: string,
): string[] {
  const cmd = asRecord(asRecord(doc.services)[service]).command;
  if (Array.isArray(cmd)) {
    return cmd.map((c) => asString(c)).filter((c): c is string => c !== null);
  }
  if (typeof cmd === "string") {
    return cmd.split(/\s+/).filter(Boolean);
  }
  return [];
}

/** Configuration flags other than `--configFile`. */
export function hasConfigFlags(args: string[]): boolean {
  return args.some((a) =>
    /^--?[^-]/.test(a) && !/^--?configfile(=|$)/i.test(a)
  );
}

/** The `--configFile` value, in `--configFile=x` or `--configFile x` form. */
export function configFileFlag(args: string[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const m = args[i].match(/^--?configfile(?:=(.*))?$/i);
    if (!m) continue;
    const v = m[1] ?? args[i + 1];
    return v ? unquote(v) : null;
  }
  return null;
}

/**
 * The paths Traefik tries for a static file, in its own order (paerser's
 * Finder): the `--configFile` value, then `/etc/traefik/traefik`,
 * `$XDG_CONFIG_HOME/traefik`, `$HOME/.config/traefik` and `./traefik`, each
 * as .toml, .yaml, .yml. The first that exists is read, and then every CLI
 * flag is ignored: the file loader runs before the flag loader. In the
 * official image the working directory is `/`, HOME is `/root` and
 * XDG_CONFIG_HOME is unset (so that base expands to `/traefik`).
 */
export function staticCandidates(args: string[], workDir = "/"): string[] {
  const out: string[] = [];
  const named = configFileFlag(args);
  if (named) out.push(containerPath(named, workDir));
  for (
    const base of [
      "/etc/traefik/traefik",
      "/traefik",
      "/root/.config/traefik",
      "./traefik",
    ]
  ) {
    for (const ext of ["toml", "yaml", "yml"]) {
      out.push(containerPath(`${base}.${ext}`, workDir));
    }
  }
  return [...new Set(out)];
}

/** Normalise a container path, resolving a relative one against `workDir`. */
export function containerPath(p: string, workDir: string): string {
  const full = p.startsWith("/") ? p : `${workDir.replace(/\/+$/, "")}/${p}`;
  const parts: string[] = [];
  for (const x of full.split("/")) {
    if (x === "" || x === ".") continue;
    if (x === "..") parts.pop();
    else parts.push(x);
  }
  return "/" + parts.join("/");
}

/** A volume of the Traefik service, as far as the repository can tell. */
export interface Mount {
  target: string;
  /** Repository path for a bind mount of a path inside the repository, else null. */
  repoPath: string | null;
}

/** Normalise a repository path; null when it escapes the repository root. */
function repoJoin(dir: string, rel: string): string | null {
  const parts: string[] = [];
  for (const x of `${dir}/${rel}`.split("/")) {
    if (x === "" || x === ".") continue;
    if (x === "..") {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(x);
  }
  return parts.join("/");
}

/**
 * The service's volumes. A bind source starting with `.` resolves against the
 * compose file's directory; anything else (an absolute or `~` path, a named or
 * anonymous volume, a variable) is outside what the repository says.
 */
export function serviceMounts(
  doc: Record<string, unknown>,
  service: string,
  composeDir: string,
): Mount[] {
  const vols = asRecord(asRecord(doc.services)[service]).volumes;
  if (!Array.isArray(vols)) return [];
  const out: Mount[] = [];
  for (const v of vols) {
    let source: string | null = null;
    let target: string | null = null;
    if (typeof v === "string") {
      const parts = v.split(":");
      if (parts.length === 1) target = parts[0];
      else [source, target] = parts;
    } else {
      const r = asRecord(v);
      target = asString(r.target);
      source = r.type === "bind" || r.type === undefined
        ? asString(r.source)
        : null;
    }
    if (!target) continue;
    const repoPath = source && source.startsWith(".")
      ? repoJoin(composeDir, source)
      : null;
    out.push({ target: containerPath(target, "/"), repoPath });
  }
  return out;
}

/** Where the static file Traefik will read comes from. */
export type StaticLocation =
  | { kind: "file"; repoPath: string; containerPath: string }
  | { kind: "external"; containerPath: string }
  | { kind: "absent" };

/**
 * Find the static file Traefik reads, by walking its candidate paths through
 * the service's mounts. A candidate under no mount is taken as absent from
 * the image (the official image ships none). A candidate under a mount the
 * repository does not describe is `external`: it may exist, so the source is
 * unknown. A file bind-mounted from a repository path that does not exist is
 * external too (a deploy step may create it); a directory mount whose
 * repository copy lacks the file does not provide it.
 */
export async function locateStaticFile(
  candidates: string[],
  mounts: Mount[],
  exists: (repoPath: string) => Promise<boolean>,
): Promise<StaticLocation> {
  for (const cand of candidates) {
    const m = mounts
      .filter((x) =>
        cand === x.target || cand.startsWith(`${x.target.replace(/\/$/, "")}/`)
      )
      .sort((a, b) => b.target.length - a.target.length)[0];
    if (!m) continue;
    if (m.repoPath === null) return { kind: "external", containerPath: cand };
    const rest = cand.slice(m.target.replace(/\/$/, "").length).replace(
      /^\//,
      "",
    );
    const repoPath = rest ? repoJoin(m.repoPath, rest) : m.repoPath;
    if (repoPath === null) return { kind: "external", containerPath: cand };
    if (await exists(repoPath)) {
      return { kind: "file", repoPath, containerPath: cand };
    }
    if (!rest) return { kind: "external", containerPath: cand };
  }
  return { kind: "absent" };
}

/** Read the static settings this model needs out of CLI flags. */
export function staticFromCli(args: string[]): StaticSettings {
  const flags = new Map<string, string>();
  // Plugin names keep the case they were written in.
  const raw: [string, string][] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const m = a.match(/^--?([^-=][^=]*)(?:=(.*))?$/);
    if (!m) continue;
    // `--key value` is also accepted for non-boolean flags.
    let value = m[2];
    if (value === undefined) {
      const next = args[i + 1];
      value = next !== undefined && !next.startsWith("-")
        ? (i++, next)
        : "true";
    }
    flags.set(m[1].toLowerCase(), unquote(value));
    raw.push([m[1], unquote(value)]);
  }
  const plugins = new Map<string, PluginDecl>();
  for (const [k, v] of raw) {
    const m = `${k}=${v}`.match(
      /^experimental\.(plugins|localplugins)\.([^.=]+)\.(modulename|version)=(.*)$/i,
    );
    if (!m) continue;
    const mode = m[1].toLowerCase() === "plugins" ? "remote" : "local";
    const key = `${mode}:${m[2]}`;
    const decl = plugins.get(key) ?? {
      name: m[2],
      moduleName: "",
      version: null,
      mode,
      source: "cli",
    } as PluginDecl;
    if (m[3].toLowerCase() === "modulename") decl.moduleName = unquote(m[4]);
    else decl.version = unquote(m[4]);
    plugins.set(key, decl);
  }
  return {
    apiInsecure: (flags.get("api.insecure") ?? "").toLowerCase() === "true",
    logFilePath: flags.get("log.filepath") ?? null,
    apiEntrypointPort: portOf(flags.get("entrypoints.traefik.address")) ?? 8080,
    plugins: [...plugins.values()].filter((p) => p.moduleName),
  };
}

function portOf(address: string | null | undefined): number | null {
  if (!address) return null;
  const m = unquote(address).match(/:(\d+)(\/\w+)?$/);
  return m ? parseInt(m[1], 10) : null;
}

/**
 * A field of a parsed static file. Traefik's decoder matches field names
 * case-insensitively (`modulename`, `Experimental`), so this does too.
 */
function field(rec: Record<string, unknown>, key: string): unknown {
  if (key in rec) return rec[key];
  const k = Object.keys(rec).find((x) => x.toLowerCase() === key.toLowerCase());
  return k === undefined ? undefined : rec[k];
}

/** Read the static settings out of a parsed TOML or YAML static file. */
export function staticFromDocument(
  doc: Record<string, unknown>,
): StaticSettings {
  const experimental = asRecord(field(doc, "experimental"));
  const plugins: PluginDecl[] = [];
  for (
    const [key, mode] of [
      ["plugins", "remote"],
      ["localPlugins", "local"],
    ] as const
  ) {
    for (
      const [name, raw] of Object.entries(asRecord(field(experimental, key)))
    ) {
      const def = asRecord(raw);
      const moduleName = asString(field(def, "moduleName"));
      if (!moduleName) continue;
      plugins.push({
        name,
        moduleName,
        version: mode === "remote" ? asString(field(def, "version")) : null,
        mode,
        source: "file",
      });
    }
  }
  const api = asRecord(field(doc, "api"));
  const eps = asRecord(field(doc, "entryPoints"));
  const insecure = field(api, "insecure");
  return {
    apiInsecure: insecure === true || String(insecure).toLowerCase() === "true",
    logFilePath: asString(field(asRecord(field(doc, "log")), "filePath")),
    apiEntrypointPort:
      portOf(asString(field(asRecord(field(eps, "traefik")), "address"))) ??
        8080,
    plugins,
  };
}

/** Parse a static configuration file by extension. */
export function parseStaticFile(
  path: string,
  text: string,
): Record<string, unknown> {
  try {
    if (/\.toml$/i.test(path)) return asRecord(parseToml(text));
    return asRecord(parseYaml(text));
  } catch (err) {
    throw new Error(
      `${path} could not be parsed: ${
        err instanceof Error ? err.message : err
      }`,
    );
  }
}

function inPortSpec(spec: string, port: number): boolean {
  const m = spec.match(/^(\d+)(?:-(\d+))?$/);
  if (!m) return false;
  const lo = parseInt(m[1], 10);
  const hi = m[2] ? parseInt(m[2], 10) : lo;
  return port >= lo && port <= hi;
}

/**
 * Whether a compose service exposes `containerPort` on a host interface other
 * than loopback: published through `ports` (short or long syntax, single ports
 * or ranges), or reachable directly because the service uses
 * `network_mode: host`. Docker publishes through its own iptables chain, ahead
 * of a host firewall, so a published port is reachable from wherever the host
 * is unless it binds 127.0.0.1.
 */
export function publishesPort(
  doc: Record<string, unknown>,
  service: string,
  containerPort: number,
): boolean {
  const svc = asRecord(asRecord(doc.services)[service]);
  if (svc.network_mode === "host") return true;
  const ports = svc.ports;
  if (!Array.isArray(ports)) return false;
  const loopback = /^(127\.|\[?::1\]?$|localhost)/;
  for (const p of ports) {
    if (typeof p === "string" || typeof p === "number") {
      const s = String(p).replace(/\/\w+$/, "");
      const parts = s.split(":");
      // A bare container port is published on a random host port.
      const target = parts[parts.length - 1];
      const hostIp = parts.length >= 3 ? parts.slice(0, -2).join(":") : "";
      if (inPortSpec(target, containerPort) && !loopback.test(hostIp)) {
        return true;
      }
    } else {
      const r = asRecord(p);
      const hostIp = asString(r.host_ip) ?? "";
      // Without `published`, Docker picks a random host port: still published.
      if (
        inPortSpec(String(r.target ?? ""), containerPort) &&
        !loopback.test(hostIp)
      ) return true;
    }
  }
  return false;
}

/** `github.com/owner/repo[/sub]` -> `owner/repo`, else null. */
export function githubRepoOfModule(moduleName: string): string | null {
  const m = moduleName.match(/^github\.com\/([^/]+)\/([^/]+)/i);
  return m ? `${m[1]}/${m[2]}` : null;
}

// ---------------------------------------------------------------------------
// The vendoring record
// ---------------------------------------------------------------------------

function mentions(line: string, p: PluginDecl): boolean {
  const repoName = p.moduleName.split("/").pop() ?? p.name;
  const word = (s: string) =>
    new RegExp(`(^|[^\\w.-])${escapeRe(s)}($|[^\\w-])`).test(line);
  return line.includes(p.moduleName) || word(p.name) || word(repoName);
}

/**
 * The lines of a vendoring record that belong to one plugin: from the first
 * line that names it up to the next markdown heading, or the next line that
 * names a different vendored plugin. Every read and edit of the record is
 * confined to this range, so a record listing two plugins at the same version
 * never has the other plugin's line rewritten.
 */
export function recordSection(
  record: string,
  plugin: PluginDecl,
  others: PluginDecl[],
): { start: number; end: number } | null {
  const lines = record.split("\n");
  // Prefer a heading that names the plugin: an intro line naming every
  // plugin ("Vendored: bouncer and geoblock") is not anyone's section.
  const heading = lines.findIndex((l) =>
    /^#{1,6}\s/.test(l) && mentions(l, plugin)
  );
  const start = heading >= 0
    ? heading
    : lines.findIndex((l) => mentions(l, plugin));
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (
      /^#{1,6}\s/.test(lines[i]) ||
      others.some((o) => o.name !== plugin.name && mentions(lines[i], o))
    ) {
      end = i;
      break;
    }
  }
  return { start, end };
}

const VERSION_IN_TEXT =
  /(?<![\w.])v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]*[0-9A-Za-z])?(?![\w]|\.\d)/;

/** The vendored version of one plugin, read from its section of the record. */
export function vendoredVersionFromRecord(
  record: string,
  plugin: PluginDecl,
  others: PluginDecl[] = [],
): string | null {
  const sec = recordSection(record, plugin, others);
  if (!sec) return null;
  for (const line of record.split("\n").slice(sec.start, sec.end)) {
    const m = line.match(VERSION_IN_TEXT);
    if (m) return m[0];
  }
  return null;
}

/**
 * Rewrite one plugin's section of the record: its version, commit and tarball
 * checksum become the new ones. Lines outside the section are untouched.
 * Returns null when the section does not mention the old version, so a caller
 * cannot ship a re-vendor whose record still names the old one.
 */
export function updateVendorRecord(
  record: string,
  plugin: PluginDecl,
  others: PluginDecl[],
  from: string,
  to: { version: string; commit: string; sha256: string },
): string | null {
  const sec = recordSection(record, plugin, others);
  if (!sec) return null;
  const lines = record.split("\n");
  const section = lines.slice(sec.start, sec.end).join("\n");
  const versionRe = new RegExp(
    `(?<![\\w.])${escapeRe(from)}(?![\\w-]|\\.\\d)`,
    "g",
  );
  if (!versionRe.test(section)) return null;
  versionRe.lastIndex = 0;
  const commit = section.match(/\b[0-9a-f]{40}\b/)?.[0];
  const sha256 = section.match(/\b[0-9a-f]{64}\b/)?.[0];
  let out = section;
  if (commit) out = out.split(commit).join(to.commit);
  if (sha256) out = out.split(sha256).join(to.sha256);
  out = out.replace(versionRe, to.version);
  return [
    ...lines.slice(0, sec.start),
    out,
    ...lines.slice(sec.end),
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Edits: the only writes this model makes, all to text in the repository
// ---------------------------------------------------------------------------

/** One edited line, for the dry-run report and the PR body. */
export interface LineChange {
  line: number;
  before: string;
  after: string;
}

export interface TextEdit {
  text: string;
  changes: LineChange[];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Retag `image:` lines whose repository normalises to `repository` AND whose
 * tag is exactly `fromTag`. Another service on the same image at a different
 * tag (a v2 beside a v3) is left alone. Quoting, indentation and trailing
 * comments are preserved; a digest is dropped, because a new tag with the old
 * digest would pin the old content.
 */
export function editImageTag(
  text: string,
  repository: string,
  fromTag: string,
  newTag: string,
): TextEdit {
  const lines = text.split("\n");
  const changes: LineChange[] = [];
  lines.forEach((line, i) => {
    const m = line.match(/^(\s*-?\s*image:\s*)(['"]?)([^'"\s#]+)(['"]?)(.*)$/);
    if (!m) return;
    const ref = parseImageRef(m[3]);
    if (!ref || ref.repository !== repository || ref.tag !== fromTag) return;
    if (ref.tag === newTag) return;
    const base = m[3].slice(
      0,
      m[3].length - ref.tag.length -
        (ref.digest ? ref.digest.length + 1 : 0) - 1,
    );
    const updated = `${m[1]}${m[2]}${base}:${newTag}${m[4]}${m[5]}`;
    changes.push({ line: i + 1, before: line, after: updated });
    lines[i] = updated;
  });
  return { text: lines.join("\n"), changes };
}

/**
 * Change a remote plugin's pinned version wherever it is declared: a TOML
 * table, a YAML map, or a `--experimental.plugins.<name>.version=` flag (in a
 * compose `command:` or anywhere else).
 */
export function editPluginVersion(
  text: string,
  path: string,
  pluginName: string,
  newVersion: string,
): TextEdit {
  const lines = text.split("\n");
  const changes: LineChange[] = [];
  const set = (i: number, updated: string) => {
    if (updated === lines[i]) return;
    changes.push({ line: i + 1, before: lines[i], after: updated });
    lines[i] = updated;
  };
  const flag = new RegExp(
    `(--experimental\\.plugins\\.${
      escapeRe(pluginName)
    }\\.version=)(['"]?)([^\\s'"]+)`,
    "i",
  );
  lines.forEach((line, i) => {
    if (flag.test(line)) set(i, line.replace(flag, `$1$2${newVersion}`));
  });
  if (/\.toml$/i.test(path)) {
    // Section names are matched case-insensitively, as Traefik decodes them;
    // the plugin's own name is matched as written.
    const header = new RegExp(
      `^\\s*\\[(\\w+)\\.(\\w+)\\.(?:"${escapeRe(pluginName)}"|${
        escapeRe(pluginName)
      })\\]\\s*(#.*)?$`,
    );
    const isHeader = (line: string) => {
      const m = line.match(header);
      return !!m && m[1].toLowerCase() === "experimental" &&
        m[2].toLowerCase() === "plugins";
    };
    let inBlock = false;
    lines.forEach((line, i) => {
      if (/^\s*\[/.test(line)) inBlock = isHeader(line);
      else if (inBlock) {
        const m = line.match(/^(\s*version\s*=\s*)(["'])([^"']*)(["'])(.*)$/i);
        if (m) set(i, `${m[1]}${m[2]}${newVersion}${m[4]}${m[5]}`);
      }
    });
  } else if (/\.ya?ml$/i.test(path)) {
    // experimental: / plugins: / <name>: / version: -- found by indentation.
    let pluginsIndent = -1;
    let nameIndent = -1;
    lines.forEach((line, i) => {
      const indent = line.search(/\S/);
      if (indent < 0 || /^\s*#/.test(line)) return;
      if (nameIndent >= 0 && indent <= nameIndent) nameIndent = -1;
      if (pluginsIndent >= 0 && indent <= pluginsIndent) pluginsIndent = -1;
      if (/^\s*plugins:\s*(#.*)?$/i.test(line)) {
        pluginsIndent = indent;
        return;
      }
      if (
        pluginsIndent >= 0 && nameIndent < 0 &&
        new RegExp(`^\\s*['"]?${escapeRe(pluginName)}['"]?:\\s*(#.*)?$`).test(
          line,
        )
      ) {
        nameIndent = indent;
        return;
      }
      if (nameIndent >= 0) {
        const m = line.match(
          /^(\s*version:\s*)(['"]?)([^'"\s#]+)(['"]?)(.*)$/i,
        );
        if (m) set(i, `${m[1]}${m[2]}${newVersion}${m[4]}${m[5]}`);
      }
    });
  }
  return { text: lines.join("\n"), changes };
}

/**
 * Mark lines that look like credentials in a plugin's `.traefik.yml` with
 * `# gitleaks:allow`. Plugin manifests ship catalog `testData`, which often
 * includes a dummy API key; Traefik ignores testData for local plugins, but a
 * secret scanner in the deploying repository's CI does not. An identical line
 * in the previous vendored copy keeps that copy's (possibly hand-written)
 * annotation.
 */
export function allowCatalogTestData(text: string, previous?: string): string {
  const annotated = new Map<string, string>();
  for (const line of (previous ?? "").split("\n")) {
    const at = line.indexOf("#");
    if (at > 0 && line.includes("gitleaks:allow")) {
      annotated.set(line.slice(0, at).trimEnd(), line);
    }
  }
  return text.split("\n").map((line) => {
    if (
      !/(key|token|secret|password)\w*\s*:\s*\S/i.test(line) ||
      line.includes("gitleaks:allow")
    ) return line;
    return annotated.get(line.trimEnd()) ?? `${line} # gitleaks:allow`;
  }).join("\n");
}

/** Directories in a plugin source tree that never ship as runtime code. */
const NON_RUNTIME_DIRS = new Set([
  ".github",
  "docs",
  "doc",
  "example",
  "examples",
  "exemples",
  "test",
  "tests",
  "testdata",
  "e2e",
  "scripts",
  "img",
  "images",
  ".devcontainer",
  ".vscode",
]);

/**
 * Choose which files of an upstream plugin tag to vendor.
 *
 * Kept:
 * - every file the previous vendored copy had (assets such as
 *   `templates/ban.html` included), unless it is a Go test file;
 * - `.traefik.yml`, `go.mod`, `go.sum`, LICENSE files;
 * - every non-test `.go` file at the top level;
 * - every file under a top-level directory that holds Go code (`pkg/`,
 *   `vendor/`, `internal/`, ...), minus test files, `testdata/`, and any
 *   non-runtime directory (examples, docs, ...) at whatever depth.
 *
 * Returned separately: new files that were not kept, outside the non-runtime
 * directories, so the PR names them for a reviewer instead of silently
 * dropping them.
 */
export function selectVendorFiles(
  paths: string[],
  previous: Set<string>,
): { keep: string[]; skippedNew: string[] } {
  const nonRuntime = (parts: string[]) =>
    parts.slice(0, -1).some((x) => NON_RUNTIME_DIRS.has(x));
  const goDirs = new Set<string>();
  for (const p of paths) {
    const parts = p.split("/");
    if (parts.length > 1 && p.endsWith(".go") && !nonRuntime(parts)) {
      goDirs.add(parts[0]);
    }
  }
  const keep: string[] = [];
  const skipped: string[] = [];
  for (const p of paths) {
    const parts = p.split("/");
    const isTest = /_test\.go$/.test(p) || parts.includes("testdata");
    if (isTest) continue;
    if (previous.has(p)) {
      keep.push(p);
      continue;
    }
    if (parts.length === 1) {
      if (
        p === ".traefik.yml" || p === "go.mod" || p === "go.sum" ||
        /^licen[cs]e/i.test(p) || p.endsWith(".go")
      ) keep.push(p);
      else skipped.push(p);
      continue;
    }
    if (nonRuntime(parts)) continue;
    if (goDirs.has(parts[0])) keep.push(p);
    else skipped.push(p);
  }
  return { keep: keep.sort(), skippedNew: skipped.sort() };
}

/**
 * The git blob id of some content: sha1 of `blob <length>\0<content>`. Lets
 * a re-vendor skip files whose content did not change, so the PR lists only
 * real changes.
 */
export async function gitBlobSha(content: Uint8Array): Promise<string> {
  const header = new TextEncoder().encode(`blob ${content.length}\0`);
  const buf = new Uint8Array(header.length + content.length);
  buf.set(header);
  buf.set(content, header.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", buf));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

function callSignal(timeoutMs: number, outer?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return outer ? AbortSignal.any([outer, timeout]) : timeout;
}

async function errorBody(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 300);
  } catch {
    return "<unreadable body>";
  }
}

/** Encode a git ref for a URL path: each `/`-separated segment on its own. */
export function refPath(ref: string): string {
  return ref.split("/").map(encodeURIComponent).join("/");
}

/** One upstream release, as far as this model cares. */
export interface Release {
  tag: string;
  url: string;
  version: ParsedVersion;
}

/** An open pull request, as far as this model cares. */
export interface PullRef {
  number: number;
  url: string;
  title: string;
  head: string;
  author: string;
}

/** Where upstream releases and tags are read. */
const UPSTREAM_API = "https://api.github.com";

/** A thin GitHub REST client: one token, one timeout, loud failures. */
export class GitHub {
  private readonly releaseCache = new Map<string, Release[]>();

  constructor(
    private readonly apiUrl: string,
    private readonly token: string | undefined,
    private readonly timeoutMs: number,
    private readonly signal?: AbortSignal,
    private readonly upstreamToken?: string,
  ) {}

  private headers(authenticated: boolean): Record<string, string> {
    const h: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "swamp-traefik",
    };
    const token = authenticated ? this.token : this.upstreamToken;
    if (token) h.Authorization = `Bearer ${token}`;
    return h;
  }

  /**
   * One request. `authenticated: false` is for upstream projects: a GitHub
   * App installation token is narrowed to the deployment's repository and is
   * not offered to anyone else's.
   */
  async request(
    method: string,
    path: string,
    opts: { body?: unknown; authenticated?: boolean; allow404?: boolean } = {},
  ): Promise<{ status: number; data: unknown; headers: Headers }> {
    const authenticated = opts.authenticated ?? true;
    // Upstream projects (Traefik, plugins) live on github.com whatever
    // githubApiUrl says, so upstreamToken never goes to another host.
    const base = authenticated ? this.apiUrl : UPSTREAM_API;
    const res = await fetch(`${base.replace(/\/+$/, "")}${path}`, {
      method,
      signal: callSignal(this.timeoutMs, this.signal),
      headers: {
        ...this.headers(authenticated),
        ...(opts.body !== undefined
          ? { "Content-Type": "application/json" }
          : {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    if (res.status === 404 && opts.allow404) {
      await res.body?.cancel();
      return { status: 404, data: null, headers: res.headers };
    }
    if (!res.ok) {
      const body = await errorBody(res);
      const limited = res.headers.get("x-ratelimit-remaining") === "0";
      let hint = "";
      if (limited) {
        hint =
          " -- GitHub rate limit exhausted; the result is UNKNOWN, not current";
      } else if (res.status === 404 && authenticated) {
        hint = this.token
          ? " -- the token cannot see this repository (wrong repo, or not in the App installation)"
          : " -- a private repository needs githubToken";
      }
      throw new Error(
        `GitHub ${method} ${path} -> HTTP ${res.status}${hint}: ${body}`,
      );
    }
    const data = res.status === 204 ? null : await res.json();
    return { status: res.status, data, headers: res.headers };
  }

  /** The commit a branch points at. */
  async branchHead(repo: string, ref: string): Promise<string> {
    const r = await this.request(
      "GET",
      `/repos/${repo}/git/ref/heads/${refPath(ref)}`,
    );
    return String(asRecord(asRecord(r.data).object).sha);
  }

  /** Whether a branch exists. */
  async branchExists(repo: string, ref: string): Promise<boolean> {
    const r = await this.request(
      "GET",
      `/repos/${repo}/git/ref/heads/${refPath(ref)}`,
      { allow404: true },
    );
    return r.status !== 404;
  }

  /** A file's text at a ref (a branch or commit), or null when absent. */
  async getFile(
    repo: string,
    path: string,
    ref: string,
  ): Promise<{ text: string; sha: string } | null> {
    const r = await this.request(
      "GET",
      `/repos/${repo}/contents/${
        path.split("/").map(encodeURIComponent).join("/")
      }?ref=${encodeURIComponent(ref)}`,
      { allow404: true },
    );
    if (r.status === 404) return null;
    const d = asRecord(r.data);
    if (d.type !== "file" || typeof d.content !== "string") {
      throw new Error(`${repo}:${path} is not a file`);
    }
    const bin = atob(d.content.replace(/\n/g, ""));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return { text: new TextDecoder().decode(bytes), sha: String(d.sha) };
  }

  /** Every blob under `prefix` at a commit, with its blob sha and mode. */
  async listTree(
    repo: string,
    commit: string,
    prefix: string,
  ): Promise<{ path: string; sha: string; mode: string }[]> {
    const r = await this.request(
      "GET",
      `/repos/${repo}/git/trees/${encodeURIComponent(commit)}?recursive=1`,
    );
    const d = asRecord(r.data);
    if (d.truncated === true) {
      throw new Error(`${repo} tree is too large to list recursively`);
    }
    const p = prefix.replace(/\/+$/, "") + "/";
    return (Array.isArray(d.tree) ? d.tree : [])
      .map(asRecord)
      .filter((e) => e.type === "blob" && String(e.path).startsWith(p))
      .map((e) => ({
        path: String(e.path),
        sha: String(e.sha),
        mode: String(e.mode),
      }));
  }

  /**
   * Every final release (and prerelease, flagged by its version), newest
   * first. Reads up to three pages, so a v2 pin is still found behind a
   * hundred v3 releases, and stops early once it reaches `stopAt` (the pin). Falls back to tags for projects that tag without
   * publishing releases. Cached per repository for the life of the client.
   */
  async releases(
    repo: string,
    stopAt: ParsedVersion | null = null,
    opts: { tags?: boolean } = {},
  ): Promise<Release[]> {
    const key = `${repo}|${
      stopAt ? `${stopAt.major}.${stopAt.minor}.${stopAt.patch}` : "all"
    }|${opts.tags ? "tags" : ""}`;
    const cached = this.releaseCache.get(key);
    if (cached) return cached;
    const collect = async (kind: "releases" | "tags") => {
      const out: { tag: string; url: string; flagged: boolean }[] = [];
      for (let page = 1; page <= 3; page++) {
        const r = await this.request(
          "GET",
          `/repos/${repo}/${kind}?per_page=100&page=${page}`,
          { authenticated: false },
        );
        const items = (Array.isArray(r.data) ? r.data : []).map(asRecord);
        for (const x of items) {
          if (kind === "releases") {
            if (x.draft === true) continue;
            out.push({
              tag: String(x.tag_name),
              url: String(x.html_url),
              flagged: x.prerelease === true,
            });
          } else {
            out.push({
              tag: String(x.name),
              url: `https://github.com/${repo}/releases/tag/${String(x.name)}`,
              flagged: false,
            });
          }
        }
        if (items.length < 100) break;
        // Releases come newest first: once a page reaches the pinned version,
        // everything newer has been seen, and further pages only spend the
        // anonymous rate limit (60 requests/hour per IP). Tags carry no such
        // order, so the tag fallback always reads every page it is allowed.
        if (
          kind === "releases" && stopAt && out.some((x) => {
            const v = parseVersion(x.tag);
            return v !== null && compareVersions(v, stopAt) <= 0;
          })
        ) break;
      }
      return out;
    };
    let list = await collect("releases");
    // Traefik's plugin catalog serves git tags, so a plugin tagged without a
    // release is still an upgrade: merge tags in. A release's own entry
    // (with its prerelease flag) wins over the bare tag.
    if (opts.tags || list.length === 0) {
      const seen = new Set(list.map((x) => x.tag));
      list = [
        ...list,
        ...(await collect("tags")).filter((x) => !seen.has(x.tag)),
      ];
    }
    const out = list
      .map((x) => ({ ...x, pin: parseTag(x.tag) }))
      .filter((x) => x.pin !== null && x.pin.variant === "")
      // A release GitHub flags as a prerelease is one, whatever its tag says.
      .map((x) => ({
        tag: x.tag,
        url: x.url,
        version: x.flagged && x.pin!.version.prerelease === null
          ? { ...x.pin!.version, prerelease: "flagged" }
          : x.pin!.version,
      }))
      .sort((a, b) => compareVersions(b.version, a.version));
    this.releaseCache.set(key, out);
    return out;
  }

  /** The commit a tag points at, dereferencing an annotated tag. */
  async tagCommit(repo: string, tag: string): Promise<string> {
    const r = await this.request(
      "GET",
      `/repos/${repo}/git/ref/tags/${refPath(tag)}`,
      { authenticated: false },
    );
    let obj = asRecord(asRecord(r.data).object);
    for (let i = 0; i < 3 && obj.type === "tag"; i++) {
      const t = await this.request(
        "GET",
        `/repos/${repo}/git/tags/${String(obj.sha)}`,
        { authenticated: false },
      );
      obj = asRecord(asRecord(t.data).object);
    }
    if (obj.type !== "commit") {
      throw new Error(`${repo} tag ${tag} does not resolve to a commit`);
    }
    return String(obj.sha);
  }

  /**
   * Open pull requests into `base`, all pages, from branches of the
   * repository itself. A fork's PR is anyone's, so it never stands in for a
   * bump.
   */
  async openPulls(repo: string, base: string): Promise<PullRef[]> {
    const out: PullRef[] = [];
    for (let page = 1; page <= 10; page++) {
      const r = await this.request(
        "GET",
        `/repos/${repo}/pulls?state=open&base=${
          encodeURIComponent(base)
        }&per_page=100&page=${page}`,
      );
      const items = (Array.isArray(r.data) ? r.data : []).map(asRecord);
      for (const p of items) {
        const headRepo = asString(asRecord(asRecord(p.head).repo).full_name);
        if (headRepo?.toLowerCase() !== repo.toLowerCase()) continue;
        out.push({
          number: Number(p.number),
          url: String(p.html_url),
          title: String(p.title),
          head: String(asRecord(p.head).ref),
          author: String(asRecord(p.user).login),
        });
      }
      if (items.length < 100) break;
    }
    return out;
  }
}

/**
 * Download the source tarball GitHub serves for a commit
 * (`/archive/<sha>.tar.gz`) and return its bytes and sha256.
 * Anonymous: the deployment's token is never sent to another project.
 */
export async function downloadSourceTarball(
  repo: string,
  commit: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ bytes: Uint8Array; sha256: string }> {
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error(`${repo}: ${commit} is not a commit sha`);
  }
  const url = `https://github.com/${repo}/archive/${commit}.tar.gz`;
  const res = await fetch(url, {
    signal: callSignal(timeoutMs * 4, signal),
    headers: { "User-Agent": "swamp-traefik" },
  });
  if (!res.ok) {
    throw new Error(
      `downloading ${url} -> HTTP ${res.status}: ${await errorBody(res)}`,
    );
  }
  const bytes = new Uint8Array(await res.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const sha256 = [...digest].map((b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
  return { bytes, sha256 };
}

/** A file extracted from a tarball. */
export interface TarFile {
  bytes: Uint8Array;
  executable: boolean;
}

/**
 * Extract a GitHub source tarball into a path -> file map, with the single
 * top-level `<repo>-<tag>/` directory stripped. Only regular files are kept;
 * links, absolute paths, empty segments and anything escaping the root are
 * dropped.
 */
export async function extractTarball(
  bytes: Uint8Array,
): Promise<Map<string, TarFile>> {
  const files = new Map<string, TarFile>();
  const stream = new Blob([new Uint8Array(bytes)]).stream()
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new UntarStream());
  for await (const entry of stream) {
    const type = entry.header.typeflag;
    // A per-file pax header (x) or GNU long name (L, K) carries the real path
    // of the next entry, which this reader does not apply. Dropping that file
    // would delete its vendored copy, so refuse instead. The global pax
    // header git writes (g, a commit comment) is harmless and skipped below.
    if (type === "x" || type === "L" || type === "K") {
      await entry.readable?.cancel();
      throw new Error(
        "the tarball uses extended headers for long paths, which this extractor does not read; refusing rather than dropping files",
      );
    }
    const parts = entry.path.split("/").slice(1);
    const path = parts.join("/");
    const isFile = type === "0" || type === "\0" || type === "";
    if (
      !isFile || !path || parts.some((x) => x === "" || x === ".." || x === ".")
    ) {
      await entry.readable?.cancel();
      continue;
    }
    files.set(path, {
      bytes: entry.readable
        ? new Uint8Array(await new Response(entry.readable).arrayBuffer())
        : new Uint8Array(),
      executable: (entry.header.mode & 0o111) !== 0,
    });
  }
  return files;
}

/** Docker Registry V2 auth challenge, discovered rather than assumed. */
export function parseAuthChallenge(
  header: string,
): { realm: string; service: string | null } | null {
  if (!/^\s*Bearer\s/i.test(header)) return null;
  const realm = header.match(/realm="([^"]+)"/i)?.[1];
  if (!realm) return null;
  return { realm, service: header.match(/service="([^"]+)"/i)?.[1] ?? null };
}

/**
 * Whether a tag resolves to a manifest. A release and a pushed image are
 * separate events; offering a version whose image does not exist yet sends a
 * deploy into a failed pull. Anything but 200/404 throws: a 429 must never
 * read as "absent".
 */
export async function imageTagExists(
  host: string,
  repository: string,
  tag: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<boolean> {
  const url = `https://${host}/v2/${repository}/manifests/${
    encodeURIComponent(tag)
  }`;
  const accept = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
  ].join(", ");
  const probe = await fetch(url, {
    method: "HEAD",
    signal: callSignal(timeoutMs, signal),
    headers: { Accept: accept },
  });
  await probe.body?.cancel();
  if (probe.status === 200) return true;
  if (probe.status === 404) return false;
  if (probe.status !== 401) {
    throw new Error(
      `registry ${host} answered HTTP ${probe.status} for ${repository}:${tag}; indeterminate, not absent`,
    );
  }
  const challenge = parseAuthChallenge(
    probe.headers.get("www-authenticate") ?? "",
  );
  if (!challenge) {
    throw new Error(
      `registry ${host} sent no parseable Bearer challenge for ${repository}`,
    );
  }
  const tokenUrl = new URL(challenge.realm);
  tokenUrl.searchParams.set("scope", `repository:${repository}:pull`);
  if (challenge.service) {
    tokenUrl.searchParams.set("service", challenge.service);
  }
  const tokenRes = await fetch(tokenUrl, {
    signal: callSignal(timeoutMs, signal),
  });
  if (!tokenRes.ok) {
    throw new Error(
      `${challenge.realm} refused an anonymous pull token for ${repository}: HTTP ${tokenRes.status}`,
    );
  }
  const tb = await tokenRes.json() as { token?: string; access_token?: string };
  const token = tb.token ?? tb.access_token;
  if (!token) {
    throw new Error(`${challenge.realm} returned no token for ${repository}`);
  }
  const res = await fetch(url, {
    method: "HEAD",
    signal: callSignal(timeoutMs, signal),
    headers: { Accept: accept, Authorization: `Bearer ${token}` },
  });
  await res.body?.cancel();
  if (res.status === 404) return false;
  if (res.ok) return true;
  throw new Error(
    `registry ${host} answered HTTP ${res.status} for ${repository}:${tag} after authenticating; indeterminate, not absent`,
  );
}

// ---------------------------------------------------------------------------
// Live reading
// ---------------------------------------------------------------------------

/**
 * Host and user reach ssh as one `user@host` argument. Refusing a leading `-`
 * and anything but plain name characters keeps either from being read as an
 * ssh option such as `-oProxyCommand=...`.
 */
export const SSH_HOST_RE = /^[A-Za-z0-9\[][A-Za-z0-9.:\[\]_-]*$/;
export const SSH_USER_RE = /^[A-Za-z_][A-Za-z0-9._-]*$/;
export const CONTAINER_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
export const CONTAINER_PATH_RE = /^\/[A-Za-z0-9._\/-]+$/;

/** The marker in log output that means plugins did not load. */
export const PLUGINS_DISABLED = "Plugins are disabled";

/**
 * The start of a Traefik application log record (v3 text, v2 text, JSON).
 * Applied on the host before `tail`, so access-log lines -- which start with
 * a client address, or a JSON object whose sorted keys start uppercase --
 * cannot crowd a real record out of the lines read.
 */
export const RECORD_START =
  '^(\\{"(level|error)"|[0-9]{4}-[0-9]{2}-[0-9]{2}T|time=")';

/** API paths read from inside the container, in order. */
export const API_PATHS = [
  "version",
  "overview",
  "http/routers?per_page=1000",
  "tcp/routers?per_page=1000",
  "udp/routers?per_page=1000",
  "http/middlewares?per_page=1000",
] as const;

/** Read when present; absent on Traefik before 2.2. */
const OPTIONAL_API_PATHS = new Set<string>([
  "tcp/routers?per_page=1000",
  "udp/routers?per_page=1000",
]);

const ROUTER_PATHS = API_PATHS.filter((p) =>
  p.endsWith("/routers?per_page=1000")
);

/**
 * The fixed script run on the host. Only validated values are interpolated:
 * a container name, an integer port and an absolute path. It runs only
 * read-only `docker` subcommands: `inspect` with four named fields,
 * `exec ... traefik version`, `exec ... wget` against the loopback API,
 * `logs` and `exec ... test/grep` for the plugin-failure marker. Every section
 * marker is preceded by a newline, because `wget` prints JSON without one. A
 * log source that cannot be read is marked (`@@NOLOGS`, `@@NOFILE`) rather
 * than read as clean.
 */
export function liveScript(
  container: string,
  apiPort: number | null,
  logFile: string | null,
): string {
  if (!CONTAINER_RE.test(container)) {
    throw new Error(`bad container name ${container}`);
  }
  if (logFile !== null && !CONTAINER_PATH_RE.test(logFile)) {
    throw new Error(`bad log file path ${logFile}`);
  }
  if (
    apiPort !== null &&
    !(Number.isInteger(apiPort) && apiPort > 0 && apiPort < 65536)
  ) {
    throw new Error(`bad API port ${apiPort}`);
  }
  const fmt =
    '{"image":{{json .Config.Image}},"status":{{json .State.Status}},"startedAt":{{json .State.StartedAt}},"restartCount":{{json .RestartCount}}}';
  const lines = [
    `c=${container}`,
    `echo; echo "@@INSPECT"`,
    `docker inspect "$c" --format '${fmt}' 2>&1 || echo "@@FAIL"`,
    `s=$(docker inspect "$c" --format '{{.State.StartedAt}}' 2>/dev/null)`,
    `echo; echo "@@VERSION"`,
    `docker exec "$c" traefik version 2>&1 | head -5`,
  ];
  if (apiPort !== null) {
    for (const p of API_PATHS) {
      lines.push(
        `echo; echo "@@API ${p}"`,
        `docker exec "$c" wget -qO- -T 5 "http://127.0.0.1:${apiPort}/api/${p}" 2>&1 || echo "@@FAIL"`,
      );
    }
  }
  lines.push(
    `echo; echo "@@LOGS"`,
    `docker logs --tail 1 "$c" >/dev/null 2>&1 || echo "@@NOLOGS"`,
    // Traefik colours text logs on stdout; drop the escapes first.
    `docker logs --since "$s" "$c" 2>&1 | grep -F "${PLUGINS_DISABLED}" | tr -d '\\033' | sed -E 's/\\[[0-9;]*m//g' | grep -E '${RECORD_START}' | tail -50 | cut -c1-4000`,
  );
  if (logFile) {
    lines.push(
      `echo; echo "@@LOGFILE"`,
      `docker exec "$c" test -r "${logFile}" || echo "@@NOFILE"`,
      `docker exec "$c" grep -F "${PLUGINS_DISABLED}" "${logFile}" 2>/dev/null | grep -E '${RECORD_START}' | tail -50 | cut -c1-4000`,
    );
  }
  lines.push(`echo; echo "@@END"`);
  return lines.join("\n") + "\n";
}

/** Split the script's output into its marked sections. */
export function splitSections(stdout: string): Map<string, string> {
  const out = new Map<string, string>();
  let key: string | null = null;
  let buf: string[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.match(/^@@(INSPECT|VERSION|API (.+)|LOGS|LOGFILE|END)$/);
    if (m) {
      if (key !== null) out.set(key, buf.join("\n").trim());
      key = m[1];
      buf = [];
      continue;
    }
    if (key !== null) buf.push(line);
  }
  if (key !== null && key !== "END") out.set(key, buf.join("\n").trim());
  return out;
}

/**
 * Describe a failed API read without quoting it. A partial read of the
 * middlewares document starts with a plugin's configuration (a LAPI key can be
 * in it), so anything that looks like JSON is withheld; only a plain error
 * line from wget is kept.
 */
export function describeApiFailure(raw: string): string {
  const text = raw.replace(/@@FAIL/g, "").trim();
  if (!text) return "no output";
  if (/^[\[{]/.test(text) || /["{}\[\]]/.test(text.split("\n")[0])) {
    return "partial or invalid JSON response (content withheld)";
  }
  return text.split("\n")[0].slice(0, 160);
}

/** A router as recorded: named fields only. */
export interface RouterRow {
  name: string;
  protocol: "http" | "tcp" | "udp";
  status: string;
  provider: string;
  error: string | null;
}

/** A middleware as recorded. Its configuration is never read. */
export interface MiddlewareRow {
  name: string;
  type: string;
  status: string;
  provider: string;
  isPlugin: boolean;
  error: string | null;
}

function errorText(v: unknown): string | null {
  if (Array.isArray(v)) return v.map(String).join("; ").slice(0, 400) || null;
  return typeof v === "string" && v ? v.slice(0, 400) : null;
}

/** Rebuild router rows from the API's JSON, named fields only. */
export function parseRouters(
  json: unknown,
  protocol: RouterRow["protocol"] = "http",
): RouterRow[] {
  return (Array.isArray(json) ? json : []).map(asRecord).map((r) => ({
    name: String(r.name ?? ""),
    protocol,
    status: String(r.status ?? ""),
    provider: String(r.provider ?? ""),
    error: errorText(r.error),
  })).filter((r) => r.name);
}

/**
 * Rebuild middleware rows. The `plugin` key -- the plugin's configuration --
 * is only tested for presence, never read, and no middleware's error text is
 * kept, because errors commonly quote the configuration they reject.
 */
export function parseMiddlewares(json: unknown): MiddlewareRow[] {
  return (Array.isArray(json) ? json : []).map(asRecord).map((r) => {
    const isPlugin = "plugin" in r;
    const error = errorText(r.error);
    return {
      name: String(r.name ?? ""),
      type: String(r.type ?? ""),
      status: String(r.status ?? ""),
      provider: String(r.provider ?? ""),
      isPlugin,
      // Withheld for every middleware, not only plugins: a middleware's error
      // can quote its own configuration (a basicAuth user line carries its
      // password hash). The name and status say which one to look at.
      error: error ? "error text withheld (it can quote configuration)" : null,
    };
  }).filter((r) => r.name);
}

/** `Version:      3.7.9` -> `3.7.9`. */
export function parseTraefikVersionOutput(text: string): string | null {
  return text.match(/^Version:\s*(\S+)/m)?.[1] ?? null;
}

/**
 * The timestamp at the start of a Traefik log line, in either the default
 * format (`2025-03-14T09:26:53Z ERR ...`) or JSON (`{"time":"..."}`).
 */
export function logLineTime(line: string): Date | null {
  const j = line.match(/"time"\s*:\s*"([^"]+)"/);
  const raw = j?.[1] ??
    line.match(
      /^(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)/,
    )?.[1];
  if (!raw) return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Whether a log line is Traefik's own "Plugins are disabled" record, and its
 * time. Only a record counts: an access log on the same stream or file can
 * carry the phrase in a request path or header that anyone can send, so a
 * line merely containing it is ignored. Recognised:
 *
 * - v3 text: `2025-03-14T09:26:53Z ERR [caller >] Plugins are disabled ...`
 * - JSON (v3 `message`, v2 `msg`): `{"level":"error","message":"Plugins are disabled ...","time":"..."}`
 * - v2 text: `time="..." level=error msg="Plugins are disabled ..."`
 */
export function pluginsDisabledRecord(
  line: string,
): { time: Date | null } | null {
  const date = (raw: string | undefined) => {
    if (!raw) return null;
    const d = new Date(raw);
    return isNaN(d.getTime()) ? null : d;
  };
  // deno-lint-ignore no-control-regex
  const trimmed = line.replace(/\x1b?\[[0-9;]*m/g, "").trim();
  if (trimmed.startsWith("{")) {
    let rec: Record<string, unknown>;
    try {
      rec = asRecord(JSON.parse(trimmed));
    } catch {
      return null;
    }
    const msg = asString(rec.message) ?? asString(rec.msg) ?? "";
    if (!msg.startsWith(PLUGINS_DISABLED)) return null;
    if (!/^(error|fatal|panic|warn|warning)$/i.test(String(rec.level ?? ""))) {
      return null;
    }
    return { time: date(asString(rec.time) ?? undefined) };
  }
  const ts = "(\\d{4}-\\d{2}-\\d{2}T[0-9:.]+(?:Z|[+-]\\d{2}:?\\d{2})?)";
  const v3 = trimmed.match(
    new RegExp(
      `^${ts}\\s+(?:ERR|ERROR|WRN|WARN|FTL|FATAL|PNC|PANIC)\\s+(?:\\S+\\s+>\\s+)?${PLUGINS_DISABLED}`,
    ),
  );
  if (v3) return { time: date(v3[1]) };
  const v2 = trimmed.match(
    new RegExp(
      `^time="([^"]+)"\\s+level=(?:error|warning|fatal|panic)\\s+msg="${PLUGINS_DISABLED}`,
    ),
  );
  if (v2) return { time: date(v2[1]) };
  return null;
}

/** What the proxy is doing right now. */
export interface Runtime {
  host: string;
  container: string;
  running: boolean;
  status: string;
  image: string;
  startedAt: string | null;
  restartCount: number | null;
  version: string | null;
  api: {
    reachable: boolean;
    via: "url" | "container" | "none";
    error: string | null;
  };
  routersChecked: boolean;
  routers: {
    total: number;
    enabled: number;
    notEnabled: RouterRow[];
    overviewErrors: number | null;
    overviewWarnings: number | null;
  };
  middlewares: {
    total: number;
    plugin: MiddlewareRow[];
    notEnabled: MiddlewareRow[];
  };
  pluginsDisabled: boolean;
  pluginsDisabledLine: string | null;
  /** Whether `docker logs` could be read at all. */
  containerLogsReadable: boolean;
  /** The log file watched for plugin failures; readable=false is a blind spot. */
  logFile: { path: string | null; readable: boolean | null };
  /**
   * true: everything was checked and nothing failed. false: something failed.
   * null: nothing failed, but router health or the plugin-failure log could
   * not be read -- not a pass.
   */
  healthy: boolean | null;
  /** Set by inspect when the repository (log file location) was unreadable. */
  repoReadError?: string;
  timestamp: string;
}

/** Fold the raw readings into a Runtime. Pure, for tests. */
export function buildRuntime(input: {
  host: string;
  container: string;
  inspectJson: string;
  versionText: string;
  api: Map<string, string | null>;
  apiVia: "url" | "container" | "none";
  apiError: string | null;
  logLines: string[];
  containerLogsReadable?: boolean;
  logFile?: { path: string | null; readable: boolean | null };
}): Runtime {
  let inspect: Record<string, unknown>;
  try {
    inspect = asRecord(JSON.parse(input.inspectJson));
  } catch {
    throw new Error(
      `docker inspect ${input.container} returned no usable state (output withheld, ${input.inspectJson.length} bytes)`,
    );
  }
  const status = String(inspect.status ?? "");
  const startedAt = asString(inspect.startedAt);
  const parseJson = (k: string): unknown => {
    const raw = input.api.get(k);
    if (raw === undefined || raw === null) return undefined;
    try {
      return JSON.parse(raw);
    } catch {
      return undefined;
    }
  };
  const versionDoc = asRecord(parseJson("version"));
  const overview = asRecord(parseJson("overview"));
  const routerDocs = ROUTER_PATHS.map((p) => parseJson(p));
  const middlewaresRaw = parseJson("http/middlewares?per_page=1000");
  // HTTP routers and middlewares are required; the TCP/UDP endpoints are
  // read when present (UDP routing arrived in Traefik 2.2), so their absence
  // on an old proxy does not discard the HTTP check.
  const reachable = input.apiVia !== "none" &&
    Array.isArray(routerDocs[0]) && Array.isArray(middlewaresRaw);
  const routers = reachable
    ? routerDocs.flatMap((d, i) =>
      Array.isArray(d)
        ? parseRouters(d, (["http", "tcp", "udp"] as const)[i])
        : []
    )
    : [];
  const middlewares = reachable ? parseMiddlewares(middlewaresRaw) : [];
  let overviewErrors: number | null = null;
  let overviewWarnings: number | null = null;
  for (const proto of ["http", "tcp", "udp"]) {
    const r = asRecord(asRecord(overview[proto]).routers);
    if (typeof r.errors === "number") {
      overviewErrors = (overviewErrors ?? 0) + r.errors;
    }
    if (typeof r.warnings === "number") {
      overviewWarnings = (overviewWarnings ?? 0) + r.warnings;
    }
  }
  const started = startedAt ? new Date(startedAt) : null;
  let pluginsDisabledLine: string | null = null;
  for (const line of input.logLines) {
    const rec = pluginsDisabledRecord(line);
    if (!rec) continue;
    const t = rec.time;
    // A log file outlives restarts; only a failure since this start counts.
    // An unparseable timestamp in a real record counts: unknown is not healthy.
    if (!t || !started || t.getTime() >= started.getTime() - 1000) {
      pluginsDisabledLine = line.slice(0, 400);
    }
  }
  const notEnabled = routers.filter((r) => r.status !== "enabled");
  const mwNotEnabled = middlewares.filter((m) => m.status !== "enabled");
  const version = parseTraefikVersionOutput(input.versionText) ??
    asString(versionDoc.Version);
  const running = status === "running";
  const logFile = input.logFile ?? { path: null, readable: null };
  const containerLogsReadable = input.containerLogsReadable ?? true;
  const failed = !running || pluginsDisabledLine !== null ||
    notEnabled.length > 0 || (overviewErrors ?? 0) > 0 ||
    mwNotEnabled.some((m) => m.isPlugin);
  const logsBlind = !containerLogsReadable && logFile.readable !== true;
  const unchecked = !reachable || logsBlind || logFile.readable === false;
  return {
    host: input.host,
    container: input.container,
    running,
    status,
    image: String(inspect.image ?? ""),
    startedAt,
    restartCount: typeof inspect.restartCount === "number"
      ? inspect.restartCount
      : null,
    version,
    api: {
      reachable,
      via: reachable ? input.apiVia : "none",
      error: reachable ? null : input.apiError,
    },
    routersChecked: reachable,
    routers: {
      total: routers.length,
      enabled: routers.length - notEnabled.length,
      notEnabled,
      overviewErrors,
      overviewWarnings,
    },
    middlewares: {
      total: middlewares.length,
      plugin: middlewares.filter((m) => m.isPlugin),
      notEnabled: mwNotEnabled,
    },
    pluginsDisabled: pluginsDisabledLine !== null,
    pluginsDisabledLine,
    containerLogsReadable,
    logFile,
    healthy: failed ? false : unchecked ? null : true,
    timestamp: new Date().toISOString(),
  };
}

/** Build the argument list for an SSH invocation. Host key checking stays on. */
export function sshArgs(
  host: string,
  user: string,
  command: string,
  opts: { strictHostKeyChecking?: string; knownHostsFile?: string } = {},
): string[] {
  const args = [
    "-o",
    `StrictHostKeyChecking=${opts.strictHostKeyChecking ?? "accept-new"}`,
    "-o",
    "ConnectTimeout=10",
    "-o",
    "BatchMode=yes",
  ];
  if (opts.knownHostsFile) {
    args.push("-o", `UserKnownHostsFile=${opts.knownHostsFile}`);
  }
  args.push(`${user}@${host}`, command);
  return args;
}

/**
 * The remote command: the script travels base64-encoded inside the command
 * line and is decoded into `sh` on the host. Nothing goes over stdin (which
 * stays closed), and no quoting in the script can interact with the remote
 * login shell.
 */
export function remoteCommand(script: string): string {
  const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(script)));
  return `echo ${b64} | base64 -d | sh`;
}

/**
 * Resolve `log.filePath` to a path inside the container. A relative path is
 * relative to Traefik's working directory, which is `/` in the official image
 * (`filePath = "traefik.log"` writes `/traefik.log`). Dropping a relative path
 * instead would silently stop watching the file a plugin failure is logged to.
 * Returns null when the value cannot be used safely.
 */
export function resolveLogFile(filePath: string | null): string | null {
  if (!filePath) return null;
  const abs = filePath.startsWith("/")
    ? filePath
    : `/${filePath.replace(/^\.\//, "")}`;
  return CONTAINER_PATH_RE.test(abs) && !abs.split("/").includes("..")
    ? abs
    : null;
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

const DEFAULT_TRACKED: Record<string, string> = {
  "traefik": "traefik/traefik",
  "crowdsecurity/crowdsec": "crowdsecurity/crowdsec",
};

const GlobalArgsSchema = z.object({
  sshHost: z.string().regex(SSH_HOST_RE, "not a plain hostname or IP")
    .describe(
      "Host running the Traefik container, reached over SSH (hostname, alias or IP).",
    ),
  sshUser: z.string().regex(SSH_USER_RE, "not a plain user name").default(
    "root",
  ).describe(
    "SSH user. Needs `docker inspect/exec/logs` on the container, nothing more.",
  ),
  strictHostKeyChecking: z.enum(["yes", "accept-new", "no"]).default(
    "accept-new",
  ).describe("OpenSSH StrictHostKeyChecking. `no` is never the default."),
  knownHostsFile: z.string().regex(CONTAINER_PATH_RE, "an absolute path")
    .optional().describe("Optional UserKnownHostsFile override."),
  container: z.string().regex(CONTAINER_RE, "not a plain container name")
    .default("traefik").describe("Name of the Traefik container on the host."),
  apiUrl: z.string().url().refine(
    (u) => !/^[a-z]+:\/\/[^/]*@/i.test(u),
    "no credentials in apiUrl",
  ).optional().describe(
    "Traefik API root reachable from where swamp runs, e.g. http://proxy:8080. " +
      "When unset (or unreachable) the API is read over SSH from inside the container.",
  ),
  apiPort: z.number().int().min(1).max(65535).optional().describe(
    "Port of the API inside the container. Defaults to the `traefik` entrypoint's " +
      "port from the static configuration, else 8080.",
  ),
  logFile: z.string().regex(CONTAINER_PATH_RE).optional().describe(
    "Log file inside the container, when Traefik logs to a file. Defaults to " +
      "`log.filePath` from the static configuration.",
  ),
  repo: z.string().regex(/^[\w.-]+\/[\w.-]+$/, "want owner/repo").optional()
    .describe(
      "GitHub repository the deployment's configuration is deployed from. Required by `check` and `bump`.",
    ),
  ref: z.string().regex(/^[\w.\/-]+$/, "a plain branch name").default("main")
    .describe("Branch `check` reads and `bump` targets."),
  composeFiles: z.array(z.string()).default(["docker-compose.yml"]).describe(
    "Compose files in the repository, relative to its root. The first one that " +
      "defines a Traefik service is the proxy; every file is scanned for tracked images.",
  ),
  staticConfig: z.string().optional().describe(
    "Static configuration file in the repository (traefik.toml / traefik.yml). " +
      "Usually unnecessary: the file Traefik reads is found through the compose volumes. " +
      "Set it when that file is mounted from outside the repository; a value that " +
      "disagrees with what Traefik reads is reported.",
  ),
  pluginsLocalDir: z.string().optional().describe(
    "Repository path that is mounted at /plugins-local. Defaults to `plugins-local` " +
      "beside the proxy's compose file.",
  ),
  vendorRecord: z.string().optional().describe(
    "File that records each vendored plugin's version and provenance. Defaults to " +
      "`<pluginsLocalDir>/README.md`. `bump` keeps the plugin's own section current.",
  ),
  localPluginVersions: z.record(z.string(), z.string()).optional().describe(
    "Explicit versions for vendored plugins, by plugin name, when the record cannot be parsed.",
  ),
  trackImages: z.record(z.string(), z.string()).default(DEFAULT_TRACKED)
    .describe(
      "Images to track, mapped to the GitHub repository whose releases define their " +
        "versions. Traefik itself is always tracked.",
    ),
  allowPrerelease: z.boolean().default(false).describe(
    "Offer release candidates as upgrade targets. Never set this on an edge proxy.",
  ),
  githubApiUrl: z.string().url().refine((u) => u.startsWith("https://"), {
    message: "githubApiUrl must be https: it carries githubToken",
  }).default("https://api.github.com"),
  // `.meta({ sensitive: true })` sits on the declaration line: the push-time
  // analyzer reads that line, not the chained describe().
  githubToken: z.string().meta({ sensitive: true }).optional().describe(
    "Token for the deployment repository only (contents + pull requests). Never " +
      "sent to upstream projects. Supply it per run, e.g. `${{ env.GH_TOKEN }}`.",
  ),
  // Declaration line again, for the analyzer.
  upstreamToken: z.string().meta({ sensitive: true }).optional().describe(
    "Optional token used ONLY to read public upstream projects (releases, " +
      "tags), to lift GitHub's anonymous limit of 60 requests/hour per IP. " +
      "Needs no scopes. Never sent to the deployment repository.",
  ),
  timeoutMs: z.number().int().positive().default(15_000).describe(
    "Abort each HTTP call after this long; SSH gets four times this.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const RouterSchema = z.object({
  name: z.string(),
  protocol: z.enum(["http", "tcp", "udp"]),
  status: z.string(),
  provider: z.string(),
  error: z.string().nullable(),
});
const MiddlewareSchema = z.object({
  name: z.string(),
  type: z.string(),
  status: z.string(),
  provider: z.string(),
  isPlugin: z.boolean(),
  error: z.string().nullable(),
});

const RuntimeSchema = z.object({
  host: z.string(),
  container: z.string(),
  running: z.boolean(),
  status: z.string(),
  image: z.string(),
  startedAt: z.string().nullable(),
  restartCount: z.number().nullable(),
  version: z.string().nullable(),
  api: z.object({
    reachable: z.boolean(),
    via: z.enum(["url", "container", "none"]),
    error: z.string().nullable(),
  }),
  routersChecked: z.boolean(),
  routers: z.object({
    total: z.number(),
    enabled: z.number(),
    notEnabled: z.array(RouterSchema),
    overviewErrors: z.number().nullable(),
    overviewWarnings: z.number().nullable(),
  }),
  middlewares: z.object({
    total: z.number(),
    plugin: z.array(MiddlewareSchema),
    notEnabled: z.array(MiddlewareSchema),
  }),
  pluginsDisabled: z.boolean(),
  pluginsDisabledLine: z.string().nullable(),
  containerLogsReadable: z.boolean(),
  logFile: z.object({
    path: z.string().nullable(),
    readable: z.boolean().nullable(),
  }),
  healthy: z.boolean().nullable(),
  repoReadError: z.string().optional(),
  timestamp: z.string(),
});

const PrSchema = z.object({
  number: z.number(),
  url: z.string(),
  title: z.string(),
  author: z.string(),
});

const ComponentSchema = z.object({
  id: z.string().describe(
    "`image:<repository>` or `plugin:<name>`; what `bump` takes.",
  ),
  kind: z.enum(["image", "plugin"]),
  name: z.string(),
  mode: z.enum(["remote", "local"]).nullable(),
  file: z.string().nullable(),
  upstream: z.string().nullable(),
  pinned: z.string().nullable(),
  otherPins: z.array(z.string()),
  running: z.string().nullable(),
  latest: z.string().nullable(),
  latestUrl: z.string().nullable(),
  newerMajor: z.string().nullable(),
  status: z.enum(["current", "behind", "ahead", "unknown"]),
  reason: z.string().nullable(),
  change: z.enum(["major", "minor", "patch"]).nullable(),
  imageAvailable: z.boolean().nullable(),
  pendingPrs: z.array(PrSchema),
  supersededPrs: z.array(PrSchema),
});

const FindingSchema = z.object({
  code: z.string(),
  severity: z.enum(["critical", "warning", "info"]),
  component: z.string().nullable(),
  message: z.string(),
});

const CheckSchema = z.object({
  host: z.string(),
  repo: z.string(),
  ref: z.string(),
  commit: z.string(),
  configSource: z.enum(["cli", "file", "none", "unknown"]),
  staticFile: z.string().nullable(),
  components: z.array(ComponentSchema),
  runtime: RuntimeSchema.nullable(),
  findings: z.array(FindingSchema),
  behind: z.boolean(),
  critical: z.boolean(),
  findingCount: z.number(),
  summary: z.string(),
  timestamp: z.string(),
});

const BumpSchema = z.object({
  repo: z.string(),
  ref: z.string(),
  baseCommit: z.string(),
  dryRun: z.boolean(),
  results: z.array(z.object({
    component: z.string(),
    from: z.string().nullable(),
    to: z.string().nullable(),
    status: z.enum([
      "would-open",
      "opened",
      "existing-pr",
      "current",
      "refused",
      "failed",
    ]),
    reason: z.string().nullable(),
    branch: z.string().nullable(),
    prUrl: z.string().nullable(),
    files: z.array(z.object({
      path: z.string(),
      action: z.enum(["modify", "add", "delete"]),
      changes: z.array(z.object({
        line: z.number(),
        before: z.string(),
        after: z.string(),
      })),
    })),
    notes: z.array(z.string()),
  })),
  opened: z.number(),
  failed: z.number(),
  timestamp: z.string(),
});

type Component = z.infer<typeof ComponentSchema>;
type Finding = z.infer<typeof FindingSchema>;
type BumpResult = z.infer<typeof BumpSchema>["results"][number];

interface Context {
  globalArgs: GlobalArgs;
  signal?: AbortSignal;
  logger: {
    info: (msg: string, meta?: Record<string, unknown>) => void;
    warn?: (msg: string, meta?: Record<string, unknown>) => void;
  };
  writeResource: (
    resource: string,
    instance: string,
    attributes: unknown,
  ) => Promise<unknown>;
}

// --- the deployment's declared configuration --------------------------------

/** Everything the repository says about the deployment, at one commit. */
export interface Desired {
  /** The commit everything below was read from; `bump` builds on it. */
  commit: string;
  traefikFile: string;
  traefikService: string;
  traefikImage: ImageRef;
  images: ComposeImage[];
  unresolved: UnresolvedImage[];
  /**
   * cli: flags configure Traefik. file: a static file does (staticFile).
   * none: neither, so Traefik runs on defaults and loads no plugin.
   * unknown: the source could not be determined (staticNote says why), so
   * plugins were NOT read -- never treated as "no plugins".
   */
  configSource: "cli" | "file" | "none" | "unknown";
  /** Repository path of the static file Traefik reads, when configSource is file. */
  staticFile: string | null;
  /** Why the source is unknown, or a staticConfig that disagrees with it. */
  staticNote: string | null;
  /** Compose `command` flags that Traefik ignores because a static file wins. */
  ignoredFlags: boolean;
  settings: StaticSettings;
  /** staticConfig names a file Traefik does not read. */
  shadowedStaticFile: string | null;
  apiPublished: boolean;
  pluginsLocalDir: string;
  vendorRecordPath: string;
  vendorRecord: string | null;
  vendoredVersions: Record<string, string | null>;
  files: Map<string, string>;
}

async function readDesired(g: GlobalArgs, gh: GitHub): Promise<Desired> {
  const repo = g.repo!;
  // Pin every read to one commit, so the plan and the PR's parent agree.
  const commit = await gh.branchHead(repo, g.ref);
  const files = new Map<string, string>();
  let traefik: {
    file: string;
    service: string;
    ref: ImageRef;
    doc: Record<string, unknown>;
  } | null = null;
  const images: ComposeImage[] = [];
  const unresolved: UnresolvedImage[] = [];
  for (const path of g.composeFiles) {
    const f = await gh.getFile(repo, path, commit);
    if (!f) {
      throw new Error(`${repo}@${g.ref}: compose file ${path} does not exist`);
    }
    files.set(path, f.text);
    const doc = parseCompose(path, f.text);
    const found = composeImages(path, doc);
    images.push(...found.images);
    unresolved.push(...found.unresolved);
    const t = found.images.find((i) => isTraefikImage(i.ref));
    if (t && !traefik) {
      traefik = { file: path, service: t.service, ref: t.ref, doc };
    }
  }
  if (!traefik) {
    throw new Error(
      `${repo}@${g.ref}: none of ${
        g.composeFiles.join(", ")
      } defines a Traefik service with a parseable image`,
    );
  }
  const args = serviceCommand(traefik.doc, traefik.service);
  let settings: StaticSettings = {
    apiInsecure: false,
    logFilePath: null,
    apiEntrypointPort: 8080,
    plugins: [],
  };
  let configSource: Desired["configSource"] = "none";
  let shadowed: string | null = null;
  let staticFile: string | null = null;
  let staticNote: string | null = null;
  const composeDir = traefik.file.includes("/")
    ? traefik.file.replace(/\/[^/]+$/, "")
    : "";
  const svc = asRecord(asRecord(traefik.doc.services)[traefik.service]);
  const workDir = asString(svc.working_dir) ?? "/";
  const located = await locateStaticFile(
    staticCandidates(args, workDir),
    serviceMounts(traefik.doc, traefik.service, composeDir),
    async (path) => (await gh.getFile(repo, path, commit)) !== null,
  );
  if (located.kind === "file") {
    staticFile = located.repoPath;
    if (g.staticConfig && g.staticConfig !== located.repoPath) {
      staticNote =
        `staticConfig is ${g.staticConfig}, but Traefik reads ${located.repoPath} (mounted at ${located.containerPath}); using the latter`;
      shadowed = g.staticConfig;
    }
  } else if (located.kind === "external") {
    if (g.staticConfig) {
      // The repository cannot show what is mounted there; staticConfig says.
      staticFile = g.staticConfig;
      staticNote =
        `${located.containerPath} is mounted from outside the repository; trusting staticConfig (${g.staticConfig}) for it`;
    } else {
      configSource = "unknown";
      staticNote =
        `Traefik may read ${located.containerPath}, which is mounted from outside the repository; set staticConfig to the repository file it holds`;
    }
  } else if (hasConfigFlags(args)) {
    configSource = "cli";
    shadowed = g.staticConfig ?? null;
  } else {
    const env = svc.environment;
    const envKeys = Array.isArray(env)
      ? env.map((e) => String(e).split("=")[0])
      : Object.keys(asRecord(env));
    if (
      envKeys.some((k) => /^TRAEFIK_/i.test(k)) || svc.env_file !== undefined
    ) {
      configSource = "unknown";
      staticNote =
        "no static file and no flags; Traefik may be configured by TRAEFIK_* environment variables, which this model does not read";
    }
    shadowed = g.staticConfig ?? null;
  }
  let ignoredFlags = false;
  if (staticFile) {
    const f = await gh.getFile(repo, staticFile, commit);
    if (!f) {
      throw new Error(
        `${repo}@${g.ref}: static config ${staticFile} does not exist`,
      );
    }
    files.set(staticFile, f.text);
    settings = staticFromDocument(parseStaticFile(staticFile, f.text));
    configSource = "file";
    ignoredFlags = hasConfigFlags(args);
  } else if (configSource === "cli") {
    settings = staticFromCli(args);
  }
  const dir = traefik.file.includes("/")
    ? traefik.file.replace(/\/[^/]+$/, "")
    : "";
  const pluginsLocalDir = g.pluginsLocalDir ??
    (dir ? `${dir}/plugins-local` : "plugins-local");
  const vendorRecordPath = g.vendorRecord ?? `${pluginsLocalDir}/README.md`;
  let vendorRecord: string | null = null;
  const vendoredVersions: Record<string, string | null> = {};
  const locals = settings.plugins.filter((p) => p.mode === "local");
  if (locals.length) {
    vendorRecord = (await gh.getFile(repo, vendorRecordPath, commit))?.text ??
      null;
    if (vendorRecord !== null) files.set(vendorRecordPath, vendorRecord);
    for (const p of locals) {
      vendoredVersions[p.name] = g.localPluginVersions?.[p.name] ??
        (vendorRecord
          ? vendoredVersionFromRecord(vendorRecord, p, locals)
          : null);
    }
  }
  return {
    commit,
    traefikFile: traefik.file,
    traefikService: traefik.service,
    traefikImage: traefik.ref,
    images,
    unresolved,
    configSource,
    staticFile,
    staticNote,
    ignoredFlags,
    settings,
    shadowedStaticFile: shadowed,
    apiPublished: settings.apiInsecure &&
      publishesPort(traefik.doc, traefik.service, settings.apiEntrypointPort),
    pluginsLocalDir,
    vendorRecordPath,
    vendorRecord,
    vendoredVersions,
    files,
  };
}

// --- live state -----------------------------------------------------------

async function readRuntime(
  g: GlobalArgs,
  opts: { apiPort: number | null; logFile: string | null },
  signal?: AbortSignal,
): Promise<Runtime> {
  const api = new Map<string, string | null>();
  let apiVia: "url" | "container" | "none" = "none";
  let apiError: string | null = null;
  if (g.apiUrl) {
    try {
      for (const p of API_PATHS) {
        const res = await fetch(`${g.apiUrl.replace(/\/+$/, "")}/api/${p}`, {
          signal: callSignal(g.timeoutMs, signal),
        });
        if (!res.ok) {
          await res.body?.cancel();
          if (res.status === 404 && OPTIONAL_API_PATHS.has(p)) continue;
          throw new Error(`HTTP ${res.status} for /api/${p}`);
        }
        const text = await res.text();
        // A login page or proxy error answering 200 is not the API: fall
        // back to reading it from inside the container.
        try {
          JSON.parse(text);
        } catch {
          throw new Error(`/api/${p} did not answer JSON`);
        }
        api.set(p, text);
      }
      apiVia = "url";
    } catch (err) {
      api.clear();
      // Only our own message or a fetch error, never response content.
      apiError = `apiUrl: ${err instanceof Error ? err.message : "failed"}`
        .slice(0, 200);
    }
  }
  const inContainerPort = apiVia === "url" ? null : opts.apiPort;
  const script = liveScript(g.container, inContainerPort, opts.logFile);
  // SSH is the only way to read a container that publishes no API; every
  // argument is validated above and the script is fixed (see liveScript).
  // swamp-quality-ignore deno-command
  const proc = new Deno.Command("ssh", {
    args: sshArgs(g.sshHost, g.sshUser, remoteCommand(script), {
      strictHostKeyChecking: g.strictHostKeyChecking,
      knownHostsFile: g.knownHostsFile,
    }),
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
    signal: callSignal(g.timeoutMs * 4, signal),
  });
  const out = await proc.output();
  const stdout = new TextDecoder().decode(out.stdout);
  if (out.code !== 0 || !stdout.includes("@@END")) {
    const stderr = new TextDecoder().decode(out.stderr).trim().slice(-400);
    throw new Error(
      `ssh ${g.sshUser}@${g.sshHost} (exit ${out.code}) did not complete the read: ${
        stderr || "<no stderr>"
      }`,
    );
  }
  const sections = splitSections(stdout);
  const inspectJson = sections.get("INSPECT") ?? "";
  if (inspectJson.includes("@@FAIL") || !inspectJson.startsWith("{")) {
    const first = inspectJson.split("\n")[0].replace("@@FAIL", "").trim();
    throw new Error(
      `container ${g.container} on ${g.sshHost}: ${
        /^Error|No such/i.test(first) ? first.slice(0, 200) : "no state"
      }`,
    );
  }
  if (inContainerPort !== null) {
    const failures: string[] = [];
    for (const p of API_PATHS) {
      const raw = sections.get(`API ${p}`) ?? "";
      let ok = !raw.includes("@@FAIL");
      if (ok) {
        try {
          JSON.parse(raw);
        } catch {
          ok = false;
        }
      }
      if (!ok) {
        // An optional endpoint may be absent (404) on an older Traefik; any
        // other failure (timeout, 5xx, partial JSON) means it went unread.
        const absent = OPTIONAL_API_PATHS.has(p) &&
          /server returned error: HTTP\/\S+ 404\b/.test(raw);
        if (!absent) failures.push(`/api/${p}: ${describeApiFailure(raw)}`);
        continue;
      }
      api.set(p, raw);
    }
    if (failures.length === 0) apiVia = "container";
    else {
      api.clear();
      apiError = [apiError, `in-container :${inContainerPort}: ${failures[0]}`]
        .filter(Boolean).join("; ");
    }
  }
  const logsSection = sections.get("LOGS") ?? "";
  const fileSection = sections.get("LOGFILE") ?? "";
  return buildRuntime({
    host: g.sshHost,
    container: g.container,
    inspectJson,
    versionText: sections.get("VERSION") ?? "",
    api,
    apiVia,
    apiError,
    containerLogsReadable: !logsSection.includes("@@NOLOGS"),
    logFile: {
      path: opts.logFile,
      readable: opts.logFile === null
        ? null
        : !fileSection.includes("@@NOFILE"),
    },
    logLines: [logsSection, fileSection]
      .flatMap((s) => s.split("\n"))
      .filter((l) => l && !l.startsWith("@@")),
  });
}

// --- comparison -------------------------------------------------------------

interface Upstream {
  target: Release | null;
  newerMajor: string | null;
}

/** Choose the upgrade target: newest release in the pinned major. */
export function chooseTarget(
  releases: Release[],
  pinned: ParsedVersion | null,
  allowPrerelease = false,
): Upstream {
  const usable = releases.filter((r) =>
    allowPrerelease || r.version.prerelease === null
  );
  if (usable.length === 0) return { target: null, newerMajor: null };
  if (!pinned) return { target: usable[0], newerMajor: null };
  const same = usable.find((r) => r.version.major === pinned.major) ?? null;
  const newer = usable.find((r) => r.version.major > pinned.major) ?? null;
  return { target: same, newerMajor: newer?.tag ?? null };
}

type PrRow = z.infer<typeof PrSchema>;

/** Authors whose `Bump x from a to b` titles are trusted. */
const TRUSTED_BUMP_AUTHORS = /^(?:app\/)?(?:dependabot|renovate)(?:\[bot\])?$/i;

/**
 * Open PRs that already move `component`: those reaching `target` or beyond
 * are `pending` (do not open another); those stopping short are `superseded`
 * (name them in the new PR). Matches Dependabot-style titles
 * (`bump <name> from X to Y`) and this model's own branches
 * (`swamp-traefik/<component>-<version>`), the latter only when the rest of the
 * branch name is exactly a version -- `plugin-geoblock-ext-v1.0.1` is not a
 * `plugin:geoblock` branch.
 */
export function relatedPrs(
  pulls: PullRef[],
  component: { kind: "image" | "plugin"; name: string },
  target: ParsedVersion | null,
  pinned: ParsedVersion | null = null,
): { pending: PrRow[]; superseded: PrRow[] } {
  const pending: PrRow[] = [];
  const superseded: PrRow[] = [];
  const repoName = component.name.split("/").pop()!;
  const prefix = `swamp-traefik/${slug(componentId(component))}-`;
  for (const p of pulls) {
    let to: ParsedVersion | null = null;
    if (p.head.startsWith(prefix)) {
      const rest = p.head.slice(prefix.length);
      to = /^v?\d+\.\d+\.\d+(-[0-9a-z.]+)?$/i.test(rest)
        ? parseVersion(rest)
        : null;
      if (!to) continue;
    } else {
      // A title is a claim anyone can write: only a dependency bot's counts,
      // and only when it moves the pin as it stands now.
      if (!TRUSTED_BUMP_AUTHORS.test(p.author)) continue;
      const m = p.title.match(/\bbump (\S+) from (\S+) to (\S+)/i);
      if (!m) continue;
      const subject = m[1].replace(/^`|`$/g, "");
      if (subject !== component.name && subject !== repoName) continue;
      const from = parseVersion(m[2].replace(/^`|`$/g, ""));
      if (pinned && (!from || compareVersions(from, pinned) !== 0)) continue;
      to = parseVersion(m[3].replace(/[`.,]+$/, ""));
    }
    if (!to) continue;
    const row = {
      number: p.number,
      url: p.url,
      title: p.title,
      author: p.author,
    };
    if (!target || compareVersions(to, target) >= 0) pending.push(row);
    else superseded.push(row);
  }
  return { pending, superseded };
}

function componentId(c: { kind: "image" | "plugin"; name: string }): string {
  return `${c.kind}:${c.name}`;
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9.]+/g, "-").replace(/^-+|-+$/g, "");
}

/** Compare a pin against a target; `reason` says why a status is unknown. */
export function statusOf(
  pinned: string | null,
  target: ParsedVersion | null,
): {
  status: Component["status"];
  change: Component["change"];
  reason: string | null;
} {
  if (!pinned) {
    return { status: "unknown", change: null, reason: "no pinned version" };
  }
  const p = parseTag(pinned);
  if (!p) {
    return {
      status: "unknown",
      change: null,
      reason: `pin "${pinned}" is not a version`,
    };
  }
  if (p.precision < 3) {
    return {
      status: "unknown",
      change: null,
      reason:
        `pin "${pinned}" is a floating tag; it moves on every pull, so what is running depends on when it was last pulled. Pin an exact version.`,
    };
  }
  if (!target) {
    return {
      status: "unknown",
      change: null,
      reason: `no upstream release found in major ${p.version.major}`,
    };
  }
  const c = compareVersions(p.version, target);
  if (c === 0) return { status: "current", change: null, reason: null };
  if (c > 0) return { status: "ahead", change: null, reason: null };
  return {
    status: "behind",
    change: bumpKind(p.version, target),
    reason: null,
  };
}

/** Turn the comparison into findings, most severe first. Pure, for tests. */
export function computeFindings(
  desired:
    & Pick<
      Desired,
      "settings" | "apiPublished" | "shadowedStaticFile" | "configSource"
    >
    & Partial<Pick<Desired, "staticFile" | "staticNote" | "ignoredFlags">>
    & { unresolved?: UnresolvedImage[] },
  components: Component[],
  runtime: Runtime | null,
): Finding[] {
  const f: Finding[] = [];
  if (runtime) {
    if (!runtime.running) {
      f.push({
        code: "container-not-running",
        severity: "critical",
        component: null,
        message: `container ${runtime.container} is ${
          runtime.status || "not running"
        }`,
      });
    }
    if (runtime.pluginsDisabled) {
      f.push({
        code: "plugins-disabled",
        severity: "critical",
        component: null,
        message:
          `Traefik disabled its plugins since it started; every router that references a plugin middleware is down. Log: ${runtime.pluginsDisabledLine}`,
      });
    }
    if (runtime.routersChecked && runtime.routers.notEnabled.length > 0) {
      f.push({
        code: "routers-not-enabled",
        severity: "critical",
        component: null,
        message:
          `${runtime.routers.notEnabled.length} of ${runtime.routers.total} routers are not enabled: ${
            runtime.routers.notEnabled.slice(0, 5).map((r) =>
              `${r.name} [${r.protocol}] (${r.status}${
                r.error ? `: ${r.error}` : ""
              })`
            ).join("; ")
          }`,
      });
    }
    const mw = runtime.middlewares.notEnabled;
    if (mw.length > 0) {
      const plugin = mw.filter((m) => m.isPlugin);
      f.push({
        code: "middlewares-not-enabled",
        severity: plugin.length ? "critical" : "warning",
        component: null,
        message: `${mw.length} middleware(s) not enabled${
          plugin.length ? `, ${plugin.length} of them plugin middleware` : ""
        }: ${
          mw.slice(0, 5).map((m) =>
            `${m.name} (${m.status}${m.error ? `: ${m.error}` : ""})`
          ).join("; ")
        }`,
      });
    }
    if (runtime.logFile.readable === false) {
      f.push({
        code: "log-file-unreadable",
        severity: "warning",
        component: null,
        message:
          `log file ${runtime.logFile.path} is not readable in the container, so a plugin failure logged only there would NOT be detected. Check log.filePath (a relative path is resolved against /).`,
      });
    }
    if (!runtime.containerLogsReadable && runtime.logFile.readable !== true) {
      f.push({
        code: "container-logs-unreadable",
        severity: "warning",
        component: null,
        message:
          "`docker logs` cannot be read (a logging driver without read support?) and no readable log file is configured, so a plugin-load failure would NOT be detected.",
      });
    }
    if (!runtime.routersChecked) {
      f.push({
        code: "api-unreachable",
        severity: "warning",
        component: null,
        message:
          `router and middleware health NOT checked -- the Traefik API was not reachable (${
            runtime.api.error ?? "no route"
          }). Serve it on an internal entrypoint (e.g. [entryPoints.traefik] :8080 + api.insecure, not published) or set apiUrl.`,
      });
    }
  }
  if (desired.configSource === "unknown") {
    f.push({
      code: "static-config-unknown",
      severity: "warning",
      component: null,
      message: `the static configuration source could not be determined (${
        desired.staticNote ?? "no reason recorded"
      }), so plugins and API exposure are NOT checked, and bump treats the deployment as one that may download plugins.`,
    });
  } else if (desired.staticNote) {
    f.push({
      code: "static-config-mismatch",
      severity: "warning",
      component: null,
      message: desired.staticNote,
    });
  }
  if (desired.configSource === "none") {
    f.push({
      code: "static-config-none",
      severity: "info",
      component: null,
      message:
        "the Traefik service has no static file where Traefik looks and no configuration flags, so it runs on defaults and loads no plugins.",
    });
  }
  if (desired.ignoredFlags) {
    f.push({
      code: "static-flags-ignored",
      severity: "warning",
      component: null,
      message:
        `the Traefik service's command has configuration flags, but Traefik reads ${
          desired.staticFile ?? "a static file"
        } and ignores every flag when a static file is found. Edits to those flags do nothing.`,
    });
  }
  for (const p of desired.settings.plugins.filter((p) => p.mode === "remote")) {
    f.push({
      code: "remote-plugin",
      severity: "warning",
      component: `plugin:${p.name}`,
      message:
        `${p.name} is downloaded from the plugin catalog on every start; if that download fails Traefik disables ALL plugins and every router using them. Vendor it into experimental.localPlugins.`,
    });
  }
  if (desired.apiPublished) {
    f.push({
      code: "insecure-api-published",
      severity: "warning",
      component: null,
      message:
        `api.insecure is on and port ${desired.settings.apiEntrypointPort} is published on a host interface; Docker publishes ahead of the host firewall, so the unauthenticated API is reachable wherever the host is.`,
    });
  }
  if (desired.shadowedStaticFile) {
    f.push({
      code: "static-config-shadowed",
      severity: "info",
      component: null,
      message:
        `${desired.shadowedStaticFile} is not read: it is not mounted where Traefik looks for a static file${
          desired.configSource === "cli"
            ? ", so CLI flags configure the proxy"
            : ""
        }. Edits to that file do nothing.`,
    });
  }
  for (const u of desired.unresolved ?? []) {
    f.push({
      code: "image-unresolved",
      severity: "info",
      component: null,
      message:
        `${u.file} service ${u.service} uses image "${u.raw}", built from variables; it is NOT checked.`,
    });
  }
  for (const c of components) {
    if (c.status === "unknown") {
      const localUnknown = c.kind === "plugin" && c.mode === "local" &&
        c.pinned === null;
      f.push({
        code: localUnknown ? "local-plugin-version-unknown" : "version-unknown",
        severity: "warning",
        component: c.id,
        message: `${c.name}: version state UNKNOWN, not current -- ${
          localUnknown
            ? "the vendoring record does not give its version; set localPluginVersions or record it"
            : c.reason
        }`,
      });
    }
    if (c.otherPins.length) {
      f.push({
        code: "mixed-pins",
        severity: "warning",
        component: c.id,
        message: `${c.name} is pinned at ${c.pinned} and also at ${
          c.otherPins.join(", ")
        } in other services; only ${c.pinned} is compared and bumped.`,
      });
    }
    if (
      c.id === "image:traefik" && runtime?.version && c.pinned &&
      parseTag(c.pinned)?.precision === 3
    ) {
      // A floating pin (v3, v3.7) cannot be compared with what runs; it is
      // already a version-unknown finding.
      const pv = parseVersion(c.pinned);
      const rv = parseVersion(runtime.version);
      if (pv && rv && compareVersions(pv, rv) !== 0) {
        f.push({
          code: "undeployed",
          severity: "warning",
          component: c.id,
          message:
            `the repository pins ${c.pinned} but ${runtime.version} is running: the last deploy did not land, or the host was changed by hand.`,
        });
      }
    }
    if (c.status === "behind") {
      const pr = c.pendingPrs[0];
      f.push({
        code: "behind",
        severity: c.imageAvailable === false ? "info" : "warning",
        component: c.id,
        message: `${c.name} ${c.pinned} -> ${c.latest} (${c.change})${
          c.imageAvailable === false ? ", image not published yet" : ""
        }${pr ? `; PR #${pr.number} open (${pr.author})` : ""}${
          c.supersededPrs.length
            ? `; stale PR(s) ${
              c.supersededPrs.map((p) => `#${p.number}`).join(", ")
            } stop short`
            : ""
        }`,
      });
    }
    if (c.newerMajor) {
      f.push({
        code: "newer-major",
        severity: "info",
        component: c.id,
        message:
          `${c.name} ${c.newerMajor} is a new major; not offered automatically.`,
      });
    }
  }
  const rank = { critical: 0, warning: 1, info: 2 };
  return f.sort((a, b) => rank[a.severity] - rank[b.severity]);
}

/** A notification-ready summary. */
export function summarise(label: string, findings: Finding[]): string {
  if (findings.length === 0) {
    return `${label}: current, healthy, nothing to do.`;
  }
  return [
    `${label}:`,
    ...findings.map((x) => `- [${x.severity}] ${x.code}: ${x.message}`),
  ].join("\n");
}

async function buildComponents(
  g: GlobalArgs,
  gh: GitHub,
  desired: Desired,
  runtime: Runtime | null,
  pulls: PullRef[],
  signal?: AbortSignal,
): Promise<Component[]> {
  const out: Component[] = [];
  const tracked: Record<string, string> = {
    ...g.trackImages,
    traefik: g.trackImages.traefik ?? "traefik/traefik",
  };
  const byRepo = new Map<string, ComposeImage[]>();
  for (const img of desired.images) {
    const key = isTraefikImage(img.ref) ? "traefik" : img.ref.repository;
    if (!tracked[key]) continue;
    byRepo.set(key, [...(byRepo.get(key) ?? []), img]);
  }
  for (const [key, imgs] of byRepo) {
    // The Traefik service's own pin first; other services' pins are reported.
    const primary = imgs.find((i) =>
      i.service === desired.traefikService && i.file === desired.traefikFile
    ) ?? imgs[0];
    const pinned = primary.ref.tag;
    const otherPins = [
      ...new Set(
        imgs.map((i) =>
          i.ref.tag ?? "<untagged>"
        ).filter((t) => t !== pinned),
      ),
    ];
    const upstream = tracked[key];
    const pin = pinned ? parseTag(pinned) : null;
    const up = chooseTarget(
      await gh.releases(upstream, pin?.version ?? null),
      pin?.version ?? null,
      g.allowPrerelease,
    );
    const st = statusOf(pinned, up.target?.version ?? null);
    const latest = up.target && pinned
      ? formatLike(pinned, up.target.tag)
      : null;
    let imageAvailable: boolean | null = null;
    if (st.status === "behind" && latest) {
      const coords = registryCoordinates(primary.ref);
      imageAvailable = await imageTagExists(
        coords.host,
        coords.repository,
        latest,
        g.timeoutMs,
        signal,
      );
    }
    const kindName = { kind: "image" as const, name: primary.ref.repository };
    const prs = relatedPrs(
      pulls,
      kindName,
      up.target?.version ?? null,
      pinned ? parseVersion(pinned) : null,
    );
    out.push({
      id: componentId(kindName),
      kind: "image",
      name: primary.ref.repository,
      mode: null,
      file: primary.file,
      upstream,
      pinned,
      otherPins,
      running: key === "traefik" ? runtime?.version ?? null : null,
      latest,
      latestUrl: up.target?.url ?? null,
      newerMajor: up.newerMajor,
      ...st,
      imageAvailable,
      pendingPrs: st.status === "behind" ? prs.pending : [],
      supersededPrs: st.status === "behind" ? prs.superseded : [],
    });
  }
  for (const p of desired.settings.plugins) {
    const upstream = githubRepoOfModule(p.moduleName);
    const pinned = p.mode === "remote"
      ? p.version
      : desired.vendoredVersions[p.name] ?? null;
    const up = upstream
      ? chooseTarget(
        await gh.releases(upstream, pinned ? parseVersion(pinned) : null, {
          tags: true,
        }),
        pinned ? parseVersion(pinned) : null,
        g.allowPrerelease,
      )
      : { target: null, newerMajor: null };
    const st = statusOf(pinned, up.target?.version ?? null);
    if (!upstream && st.status === "unknown") {
      st.reason =
        `module ${p.moduleName} is not on GitHub; its releases cannot be read`;
    }
    const kindName = { kind: "plugin" as const, name: p.name };
    const prs = relatedPrs(
      pulls,
      kindName,
      up.target?.version ?? null,
      pinned ? parseVersion(pinned) : null,
    );
    out.push({
      id: componentId(kindName),
      kind: "plugin",
      name: p.name,
      mode: p.mode,
      file: null,
      upstream,
      pinned,
      otherPins: [],
      running: null,
      latest: up.target?.tag ?? null,
      latestUrl: up.target?.url ?? null,
      newerMajor: up.newerMajor,
      ...st,
      imageAvailable: null,
      pendingPrs: st.status === "behind" ? prs.pending : [],
      supersededPrs: st.status === "behind" ? prs.superseded : [],
    });
  }
  return out;
}

function requireRepo(g: GlobalArgs): string {
  if (!g.repo) {
    throw new Error(
      "globalArguments.repo is required for this method (owner/repo)",
    );
  }
  return g.repo;
}

function liveOptions(g: GlobalArgs, desired: Desired | null) {
  return {
    apiPort: g.apiPort ?? desired?.settings.apiEntrypointPort ?? 8080,
    logFile: g.logFile ?? resolveLogFile(desired?.settings.logFilePath ?? null),
  };
}

// --- bump -----------------------------------------------------------------

interface FileChange {
  path: string;
  action: "modify" | "add" | "delete";
  changes: LineChange[];
  /** New content; null for a deletion. */
  content: Uint8Array | null;
  mode: "100644" | "100755";
}

/** A deliberate refusal: recorded as `refused`, not as a failure. */
export class Refusal extends Error {}

function planImageBump(
  desired: Desired,
  c: Component,
  to: string,
): FileChange[] {
  const out: FileChange[] = [];
  for (const [path, text] of desired.files) {
    if (!desired.images.some((i) => i.file === path)) continue;
    const e = editImageTag(text, c.name, c.pinned!, to);
    if (e.changes.length) {
      out.push({
        path,
        action: "modify",
        changes: e.changes,
        content: new TextEncoder().encode(e.text),
        mode: "100644",
      });
    }
  }
  return out;
}

function planRemotePluginBump(
  desired: Desired,
  c: Component,
  to: string,
): FileChange[] {
  // Only the source Traefik reads: a shadowed file or ignored flags would
  // change nothing that runs.
  const path = desired.configSource === "file"
    ? desired.staticFile
    : desired.configSource === "cli"
    ? desired.traefikFile
    : null;
  const text = path ? desired.files.get(path) : undefined;
  if (!path || text === undefined) {
    throw new Refusal("the static configuration Traefik reads is unknown");
  }
  const e = editPluginVersion(text, path, c.name, to);
  if (!e.changes.length) return [];
  // Re-read the edited text the way check does: exactly this plugin's
  // version must have moved, and nothing else.
  const read = (t: string) =>
    desired.configSource === "file"
      ? staticFromDocument(parseStaticFile(path, t)).plugins
      : staticFromCli(
        serviceCommand(parseCompose(path, t), desired.traefikService),
      ).plugins;
  const before = read(text);
  const after = read(e.text);
  const expected = before.map((p) =>
    p.mode === "remote" && p.name === c.name ? { ...p, version: to } : p
  );
  if (JSON.stringify(after) !== JSON.stringify(expected)) {
    throw new Refusal(
      `editing ${path} did not change exactly ${c.name}'s version to ${to}; refusing an edit whose effect cannot be confirmed`,
    );
  }
  return [{
    path,
    action: "modify",
    changes: e.changes,
    content: new TextEncoder().encode(e.text),
    mode: "100644",
  }];
}

async function planLocalPluginBump(
  g: GlobalArgs,
  gh: GitHub,
  desired: Desired,
  c: Component,
  plugin: PluginDecl,
  to: string,
  notes: string[],
  signal?: AbortSignal,
): Promise<FileChange[]> {
  const repo = requireRepo(g);
  const upstream = c.upstream!;
  const locals = desired.settings.plugins.filter((p) => p.mode === "local");
  // The record must be updatable before anything is downloaded: a re-vendor
  // whose record still names the old version reads as "behind" forever.
  if (desired.vendorRecord === null) {
    throw new Refusal(
      `no vendoring record at ${desired.vendorRecordPath}; create one naming ${plugin.name} and its version first`,
    );
  }
  const probe = updateVendorRecord(
    desired.vendorRecord,
    plugin,
    locals,
    c.pinned!,
    { version: to, commit: "0".repeat(40), sha256: "0".repeat(64) },
  );
  if (probe === null) {
    throw new Refusal(
      `${desired.vendorRecordPath} has no section for ${plugin.name} that mentions ${c.pinned}; fix the record by hand first`,
    );
  }
  const dest = `${desired.pluginsLocalDir}/src/${plugin.moduleName}`;
  const existing = await gh.listTree(repo, desired.commit, dest);
  if (existing.length === 0) {
    throw new Error(
      `${repo}@${desired.commit}: no vendored sources under ${dest}`,
    );
  }
  const existingByPath = new Map(existing.map((e) => [e.path, e]));
  const previous = new Set(existing.map((e) => e.path.slice(dest.length + 1)));
  const commit = await gh.tagCommit(upstream, to);
  // Download the commit the tag resolved to, not the tag again: a tag moved
  // in between would otherwise record one commit beside another's code.
  const tarball = await downloadSourceTarball(
    upstream,
    commit,
    g.timeoutMs,
    signal,
  );
  const files = await extractTarball(tarball.bytes);
  const { keep, skippedNew } = selectVendorFiles([...files.keys()], previous);
  if (!keep.includes(".traefik.yml")) {
    throw new Error(
      `${upstream}@${to} has no .traefik.yml; not a Traefik plugin tree`,
    );
  }
  const out: FileChange[] = [];
  const keepSet = new Set(keep);
  let unchanged = 0;
  for (const rel of keep) {
    const file = files.get(rel)!;
    let content = file.bytes;
    const path = `${dest}/${rel}`;
    if (rel === ".traefik.yml") {
      const prev = existingByPath.has(path)
        ? (await gh.getFile(repo, path, desired.commit))?.text
        : undefined;
      content = new TextEncoder().encode(
        allowCatalogTestData(new TextDecoder().decode(content), prev),
      );
    }
    const mode = file.executable ? "100755" : "100644";
    const before = existingByPath.get(path);
    if (
      before && before.mode === mode &&
      before.sha === await gitBlobSha(content)
    ) {
      unchanged++;
      continue;
    }
    out.push({
      path,
      action: before ? "modify" : "add",
      changes: [],
      content,
      mode,
    });
  }
  const deleted: string[] = [];
  for (const { path } of existing) {
    if (!keepSet.has(path.slice(dest.length + 1))) {
      out.push({
        path,
        action: "delete",
        changes: [],
        content: null,
        mode: "100644",
      });
      deleted.push(path.slice(dest.length + 1));
    }
  }
  const updated = updateVendorRecord(
    desired.vendorRecord,
    plugin,
    locals,
    c.pinned!,
    { version: to, commit, sha256: tarball.sha256 },
  )!;
  const before = desired.vendorRecord.split("\n");
  const after = updated.split("\n");
  out.push({
    path: desired.vendorRecordPath,
    action: "modify",
    changes: after.map((line, i) => ({
      line: i + 1,
      before: before[i] ?? "",
      after: line,
    })).filter((x) => x.before !== x.after),
    content: new TextEncoder().encode(updated),
    mode: "100644",
  });
  notes.push(
    `vendored from ${upstream} tag ${to} (commit ${commit}), tarball sha256 ${tarball.sha256}`,
    `${keep.length} files vendored, ${unchanged} of them unchanged (tests, examples and CI files left out)`,
  );
  if (deleted.length) {
    notes.push(`removed (no longer in ${to}): ${deleted.join(", ")}`);
  }
  if (skippedNew.length) {
    notes.push(
      `files in ${to} NOT vendored -- check whether the plugin needs them at runtime: ${
        skippedNew.join(", ")
      }`,
    );
  }
  return out;
}

function prBody(
  _g: GlobalArgs,
  c: Component,
  from: ParsedVersion,
  to: string,
  toV: ParsedVersion,
  releaseUrl: string | null,
  files: FileChange[],
  notes: string[],
  remotePlugins: PluginDecl[],
): string {
  const lines = [
    `Bumps **${c.name}** from \`${c.pinned}\` to \`${to}\` (${
      bumpKind(from, toV)
    }).`,
    "",
    releaseUrl ? `Release notes: ${releaseUrl}` : "",
    "",
    "### Files",
    ...files.map((f) => `- \`${f.path}\` (${f.action})`).slice(0, 60),
    files.length > 60 ? `- ... and ${files.length - 60} more` : "",
    "",
  ];
  if (notes.length) lines.push("### Notes", ...notes.map((n) => `- ${n}`), "");
  if (from.major === 0 && toV.major === 0 && from.minor !== toV.minor) {
    // Proposed like any minor (the goal is to stay current), but flagged:
    // semver allows a 0.x minor to break compatibility.
    lines.push(
      "### Pre-1.0 minor",
      `${c.name} is still 0.x, where a minor release may change configuration or behaviour. Read the release notes before merging.`,
      "",
    );
  }
  if (remotePlugins.length) {
    lines.push(
      "### Restart risk",
      `Merging restarts Traefik, and this deployment still downloads ${
        remotePlugins.map((p) => `\`${p.name}\``).join(", ")
      } from the plugin catalog at startup. If that download fails, every router using a plugin middleware is disabled. Watch the deploy's router check.`,
      "",
    );
  }
  lines.push(
    "### Verification",
    "The deploy job rolls this out. Afterwards, `check` on this instance must report the new version running, and no `routers-not-enabled`, `middlewares-not-enabled` or `plugins-disabled`.",
    "",
    // No host name: a deployment repository may be public.
    "Opened by `@sntxrr/traefik` `bump`.",
  );
  return lines.filter((l, i, a) => !(l === "" && a[i - 1] === "")).join("\n");
}

async function openPr(
  g: GlobalArgs,
  gh: GitHub,
  baseCommit: string,
  branch: string,
  title: string,
  body: string,
  files: FileChange[],
): Promise<string> {
  const repo = requireRepo(g);
  const baseObj = await gh.request(
    "GET",
    `/repos/${repo}/git/commits/${baseCommit}`,
  );
  const baseTree = String(asRecord(asRecord(baseObj.data).tree).sha);
  const tree: Record<string, unknown>[] = [];
  for (const f of files) {
    if (f.content === null) {
      tree.push({ path: f.path, mode: f.mode, type: "blob", sha: null });
      continue;
    }
    let bin = "";
    for (let i = 0; i < f.content.length; i += 0x8000) {
      bin += String.fromCharCode(...f.content.subarray(i, i + 0x8000));
    }
    const blob = await gh.request("POST", `/repos/${repo}/git/blobs`, {
      body: { content: btoa(bin), encoding: "base64" },
    });
    tree.push({
      path: f.path,
      mode: f.mode,
      type: "blob",
      sha: String(asRecord(blob.data).sha),
    });
  }
  const newTree = await gh.request("POST", `/repos/${repo}/git/trees`, {
    body: { base_tree: baseTree, tree },
  });
  // Parent is the commit the plan was read from, never the branch's current
  // head: building on a newer head would revert whatever landed in between.
  const commit = await gh.request("POST", `/repos/${repo}/git/commits`, {
    body: {
      message: title,
      tree: String(asRecord(newTree.data).sha),
      parents: [baseCommit],
    },
  });
  await gh.request("POST", `/repos/${repo}/git/refs`, {
    body: {
      ref: `refs/heads/${branch}`,
      sha: String(asRecord(commit.data).sha),
    },
  });
  const pr = await gh.request("POST", `/repos/${repo}/pulls`, {
    body: { title, head: branch, base: g.ref, body },
  });
  return String(asRecord(pr.data).html_url);
}

/** Plan (and, unless dry-run, open) the PR for one component. */
async function bumpOne(
  g: GlobalArgs,
  gh: GitHub,
  desired: Desired,
  c: Component,
  args: {
    toVersion?: string;
    dryRun: boolean;
    allowMajor: boolean;
    allowRemotePlugins: boolean;
  },
  remotePlugins: PluginDecl[],
  pulls: PullRef[],
  base: BumpResult,
  signal?: AbortSignal,
): Promise<BumpResult> {
  const pin = c.pinned ? parseTag(c.pinned) : null;
  if (!pin || pin.precision < 3) {
    throw new Refusal(c.reason ?? "pinned version unknown; see check");
  }
  let release: Release | null = null;
  if (args.toVersion) {
    const want = parseVersion(args.toVersion);
    if (!want || !c.upstream) {
      throw new Refusal(`toVersion ${args.toVersion} is not a version`);
    }
    // No early stop: an explicit target may sit pages below interleaved
    // releases of another major.
    release = (await gh.releases(c.upstream, null, {
      tags: c.kind === "plugin",
    })).find((r) => compareVersions(r.version, want) === 0) ?? null;
    if (!release) {
      throw new Refusal(
        `${c.upstream} has no release ${args.toVersion}; refusing to pin a version that does not exist`,
      );
    }
  } else if (c.latest && c.latestUrl) {
    release = {
      tag: c.latest,
      url: c.latestUrl,
      version: parseVersion(c.latest)!,
    };
  }
  if (!release) throw new Refusal(c.reason ?? "no upstream target; see check");
  const toV = release.version;
  // An image tag follows the pin's own style (v-prefix, variant). A plugin
  // version must be the upstream git tag exactly: Traefik downloads that tag,
  // and a restyled one fails to download at startup -- disabling every plugin.
  const to = c.kind === "plugin"
    ? release.tag
    : formatLike(c.pinned!, release.tag);
  base.to = to;
  if (compareVersions(toV, pin.version) <= 0) {
    return { ...base, status: "current", reason: `already at ${c.pinned}` };
  }
  if (toV.major !== pin.version.major && !args.allowMajor) {
    throw new Refusal(`${to} is a major upgrade; set allowMajor`);
  }
  if (remotePlugins.length && !args.allowRemotePlugins) {
    throw new Refusal(
      `this deployment downloads ${
        remotePlugins.map((p) => p.name).join(", ")
      } at startup; a merge restarts Traefik and risks a plugin-download outage. Vendor the plugins first, or set allowRemotePlugins.`,
    );
  }
  if (desired.configSource === "unknown" && !args.allowRemotePlugins) {
    // Plugins were not read, so "none found" is not "none downloaded".
    throw new Refusal(
      "the static configuration source is unknown, so whether this deployment downloads plugins at startup is unknown; a merge restarts Traefik. Set staticConfig (see the static-config-unknown finding), or set allowRemotePlugins.",
    );
  }
  const prs = relatedPrs(pulls, c, toV, pin.version);
  if (prs.pending.length) {
    return {
      ...base,
      status: "existing-pr",
      prUrl: prs.pending[0].url,
      reason: `PR #${prs.pending[0].number} by ${
        prs.pending[0].author
      } already moves it`,
    };
  }
  if (c.kind === "image") {
    const img = desired.images.find((i) =>
      i.ref.repository === c.name && i.ref.tag === c.pinned
    )!;
    const coords = registryCoordinates(img.ref);
    const exists = await imageTagExists(
      coords.host,
      coords.repository,
      to,
      g.timeoutMs,
      signal,
    );
    if (!exists) {
      throw new Refusal(`image ${c.name}:${to} is not published yet`);
    }
  }
  const notes: string[] = prs.superseded.map((pr) =>
    `supersedes #${pr.number} (${pr.title}), which stops short of ${to}; close it once this merges`
  );
  let files: FileChange[];
  if (c.kind === "image") {
    files = planImageBump(desired, c, to);
  } else {
    const plugin = desired.settings.plugins.find((p) => p.name === c.name)!;
    files = plugin.mode === "remote"
      ? planRemotePluginBump(desired, c, to)
      : await planLocalPluginBump(g, gh, desired, c, plugin, to, notes, signal);
  }
  if (files.length === 0) {
    throw new Refusal("no editable pin found in the repository");
  }
  const branch = `swamp-traefik/${slug(c.id)}-${slug(to)}`;
  const title = `chore(traefik): bump ${c.name} from ${c.pinned} to ${to}`;
  const report = files.map((f) => ({
    path: f.path,
    action: f.action,
    changes: f.changes,
  }));
  if (await gh.branchExists(requireRepo(g), branch)) {
    // Not covered by an open PR (that would be `existing-pr` above): a branch
    // left by a closed PR or a run that died before opening one.
    throw new Refusal(
      `branch ${branch} already exists without an open PR (left by a closed PR or an interrupted run); delete it to retry`,
    );
  }
  if (args.dryRun) {
    return { ...base, status: "would-open", branch, files: report, notes };
  }
  const prUrl = await openPr(
    g,
    gh,
    desired.commit,
    branch,
    title,
    prBody(
      g,
      c,
      pin.version,
      to,
      toV,
      release.url,
      files,
      notes,
      remotePlugins,
    ),
    files,
  );
  return { ...base, status: "opened", branch, prUrl, files: report, notes };
}

// --- definition -----------------------------------------------------------

/**
 * The `@sntxrr/traefik/instance` model: one Traefik deployment, its host and
 * the repository it is deployed from.
 */
export const model = {
  type: "@sntxrr/traefik/instance",
  description:
    "One Traefik deployment: its live state (version, router and middleware health, whether plugins loaded), how far its pinned Traefik, sidecar images and plugins have fallen behind upstream, and pull requests that bump them. `inspect` and `check` are read-only; `bump` writes only a pull request to the deployment's repository, dry-run by default.",
  version: "2026.10.25.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    runtime: {
      description:
        "What the proxy is doing right now: version, routers, middlewares, plugin load.",
      schema: RuntimeSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    check: {
      description:
        "Pinned vs running vs upstream for Traefik, tracked images and every plugin, with findings.",
      schema: CheckSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    bump: {
      description: "What `bump` planned or opened, per component.",
      schema: BumpSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },
  methods: {
    inspect: {
      description:
        "Read-only. The live proxy: running version, start time, HTTP/TCP/UDP router and middleware status, and whether plugins failed to load since this start. Uses apiUrl when reachable, else the API from inside the container over SSH. healthy is null, not true, when router health or the plugin-failure log could not be read.",
      arguments: z.object({}),
      execute: async (_args: Record<never, never>, context: Context) => {
        const g = context.globalArgs;
        let desired: Desired | null = null;
        let repoError: string | null = null;
        if (g.repo) {
          // Optional: the repository supplies the API port and log file.
          // inspect still works without it.
          try {
            desired = await readDesired(
              g,
              new GitHub(
                g.githubApiUrl,
                g.githubToken,
                g.timeoutMs,
                context.signal,
                g.upstreamToken,
              ),
            );
          } catch (err) {
            repoError = err instanceof Error ? err.message : String(err);
            (context.logger.warn ?? context.logger.info)(
              "repository not read ({error}); using defaults",
              { error: repoError },
            );
          }
        }
        const runtime = await readRuntime(
          g,
          liveOptions(g, desired),
          context.signal,
        );
        if (repoError !== null && !g.logFile) {
          // The repository says where Traefik logs. Without it, a plugin
          // failure written to a log file would go unseen: not a pass.
          runtime.repoReadError = repoError.slice(0, 300);
          if (runtime.healthy === true) runtime.healthy = null;
        }
        context.logger.info(
          "{host}: Traefik {version} {status}, routers {enabled}/{total}{checked}, plugins disabled={disabled}, healthy={healthy}",
          {
            host: g.sshHost,
            version: runtime.version ?? "?",
            status: runtime.status,
            enabled: runtime.routers.enabled,
            total: runtime.routers.total,
            checked: runtime.routersChecked ? "" : " (NOT checked)",
            disabled: runtime.pluginsDisabled,
            healthy: String(runtime.healthy),
          },
        );
        await context.writeResource("runtime", "runtime", runtime);
        return runtime;
      },
    },
    check: {
      description:
        "Read-only. Compare the repository's pins (Traefik, tracked images, every plugin) with what is running and with upstream releases; flag remote plugins, undeployed pins, a published insecure API, disabled routers or plugin middlewares, and anything that could not be determined. Notes open PRs (Dependabot's or bump's) that already move a component.",
      arguments: z.object({
        live: z.boolean().default(true).describe(
          "Read the live proxy too. false compares the repository with upstream only.",
        ),
      }),
      execute: async (args: { live: boolean }, context: Context) => {
        const g = context.globalArgs;
        const repo = requireRepo(g);
        const gh = new GitHub(
          g.githubApiUrl,
          g.githubToken,
          g.timeoutMs,
          context.signal,
          g.upstreamToken,
        );
        const desired = await readDesired(g, gh);
        const runtime = args.live
          ? await readRuntime(g, liveOptions(g, desired), context.signal)
          : null;
        const pulls = await gh.openPulls(repo, g.ref);
        const components = await buildComponents(
          g,
          gh,
          desired,
          runtime,
          pulls,
          context.signal,
        );
        const findings = computeFindings(desired, components, runtime);
        const result = {
          host: g.sshHost,
          repo,
          ref: g.ref,
          commit: desired.commit,
          configSource: desired.configSource,
          staticFile: desired.staticFile,
          components,
          runtime,
          findings,
          behind: components.some((c) =>
            c.status === "behind" && c.imageAvailable !== false
          ),
          critical: findings.some((x) => x.severity === "critical"),
          findingCount: findings.length,
          summary: summarise(`${g.sshHost} (${repo})`, findings),
          timestamp: new Date().toISOString(),
        };
        context.logger.info(
          "{host}: {count} findings, behind={behind}, critical={critical}",
          {
            host: g.sshHost,
            count: findings.length,
            behind: result.behind,
            critical: result.critical,
          },
        );
        await context.writeResource("check", "check", result);
        return result;
      },
    },
    bump: {
      description:
        "Open one pull request per component that is behind, in the deployment's repository: an image tag, a remote plugin version, or a re-vendored local plugin with its provenance recorded. DRY-RUN BY DEFAULT. Never merges and never touches the host. Skips components with an open PR already; refuses major upgrades unless allowMajor, target versions that do not exist upstream, and instances that download plugins at startup unless allowRemotePlugins. Each component is independent: one failing is recorded and the rest still run; the method fails at the end if any did.",
      arguments: z.object({
        component: z.string().default("all").describe(
          "`all` (every component that is behind), or one id from `check`: `image:traefik`, `image:crowdsecurity/crowdsec`, `plugin:<name>`.",
        ),
        toVersion: z.string().optional().describe(
          "Target version for a single component; must be an upstream release. Defaults to the newest stable release in its major.",
        ),
        dryRun: z.boolean().default(true).describe(
          "true (default) plans and reports the exact edits; false opens the pull requests.",
        ),
        allowMajor: z.boolean().default(false).describe(
          "Permit a toVersion in a new major. Read the migration guide first.",
        ),
        allowRemotePlugins: z.boolean().default(false).describe(
          "Open PRs even though this deployment downloads plugins at startup, so every merge risks a plugin-download outage.",
        ),
      }),
      execute: async (
        args: {
          component: string;
          toVersion?: string;
          dryRun: boolean;
          allowMajor: boolean;
          allowRemotePlugins: boolean;
        },
        context: Context,
      ) => {
        const g = context.globalArgs;
        const repo = requireRepo(g);
        if (!args.dryRun && !g.githubToken) {
          throw new Error("bump with dryRun=false needs githubToken");
        }
        if (args.toVersion && args.component === "all") {
          throw new Error("toVersion needs a single component, not `all`");
        }
        const gh = new GitHub(
          g.githubApiUrl,
          g.githubToken,
          g.timeoutMs,
          context.signal,
          g.upstreamToken,
        );
        const desired = await readDesired(g, gh);
        const pulls = await gh.openPulls(repo, g.ref);
        const components = await buildComponents(
          g,
          gh,
          desired,
          null,
          pulls,
          context.signal,
        );
        const remotePlugins = desired.settings.plugins.filter((p) =>
          p.mode === "remote"
        );
        const selected = args.component === "all"
          ? components.filter((c) => c.status === "behind")
          : components.filter((c) => c.id === args.component);
        if (args.component !== "all" && selected.length === 0) {
          throw new Error(
            `no component ${args.component}; known: ${
              components.map((c) => c.id).join(", ")
            }`,
          );
        }
        const results: BumpResult[] = [];
        for (const c of selected) {
          const base: BumpResult = {
            component: c.id,
            from: c.pinned,
            to: null,
            status: "refused",
            reason: null,
            branch: null,
            prUrl: null,
            files: [],
            notes: [],
          };
          try {
            results.push(
              await bumpOne(
                g,
                gh,
                desired,
                c,
                args,
                remotePlugins,
                pulls,
                base,
                context.signal,
              ),
            );
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            results.push({
              ...base,
              status: err instanceof Refusal ? "refused" : "failed",
              reason: message.slice(0, 500),
            });
          }
        }
        const result = {
          repo,
          ref: g.ref,
          baseCommit: desired.commit,
          dryRun: args.dryRun,
          results,
          opened: results.filter((r) => r.status === "opened").length,
          failed: results.filter((r) => r.status === "failed").length,
          timestamp: new Date().toISOString(),
        };
        for (const r of results) {
          context.logger.info("{component}: {status} {from} -> {to} {detail}", {
            component: r.component,
            status: r.status,
            from: r.from ?? "?",
            to: r.to ?? "?",
            detail: r.prUrl ?? r.reason ?? "",
          });
        }
        // Record what happened -- including PRs already opened -- before
        // failing, so a partial run is never lost.
        await context.writeResource("bump", "bump", result);
        if (result.failed > 0) {
          throw new Error(
            `bump failed for ${
              results.filter((r) => r.status === "failed").map((r) =>
                `${r.component} (${r.reason})`
              ).join("; ")
            }; ${result.opened} PR(s) opened, recorded in the bump resource`,
          );
        }
        return result;
      },
    },
  },
};
