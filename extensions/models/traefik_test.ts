import {
  assert,
  assertEquals,
  assertFalse,
  assertStringIncludes,
} from "jsr:@std/assert@1.0.19";
import {
  allowCatalogTestData,
  buildRuntime,
  bumpOne,
  chooseTarget,
  compareVersions,
  composeImages,
  computeFindings,
  configFileFlag,
  describeApiFailure,
  editImageTag,
  editPluginVersion,
  extractTarball,
  formatLike,
  gitBlobSha,
  GitHub,
  githubRepoOfModule,
  hasConfigFlags,
  liveScript,
  locateStaticFile,
  logLineTime,
  model,
  parseCompose,
  parseImageRef,
  parseMiddlewares,
  parseStaticFile,
  parseTag,
  parseVersion,
  type PluginDecl,
  pluginsDisabledRecord,
  prBody,
  publishesPort,
  recordSection,
  refPath,
  Refusal,
  registryCoordinates,
  relatedPrs,
  type Release,
  remoteCommand,
  resolveLogFile,
  selectVendorFiles,
  serviceCommand,
  serviceMounts,
  splitSections,
  sshArgs,
  staticCandidates,
  staticFromCli,
  staticFromDocument,
  statusOf,
  updateVendorRecord,
  vendoredVersionFromRecord,
} from "./traefik.ts";

// --- fixtures ---------------------------------------------------------------

const COMPOSE_FILE_CONFIG = `services:
  traefik:
    image: 'traefik:v3.7.9'   # edge proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - './traefik.toml:/traefik.toml:ro'
  crowdsec:
    image: "crowdsecurity/crowdsec:v1.7.4"
`;

const COMPOSE_CLI_CONFIG = `services:
  traefik:
    image: traefik:v3.6.9
    command:
      - --api.insecure=true
      - --api.dashboard=true
      - --experimental.plugins.crowdsec-bouncer-traefik-plugin.moduleName=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
      - --experimental.plugins.crowdsec-bouncer-traefik-plugin.version=v1.7.1
      - --experimental.plugins.Fail2Ban.moduleName=github.com/tomMoulard/fail2ban
      - --experimental.plugins.Fail2Ban.version=v0.8.9
      - --entrypoints.websecure.address=:443
    ports:
      - "80:80"
      - "8080:8080"  # API
`;

const TOML_REMOTE = `[entryPoints]
  [entryPoints.websecure]
    address = ":443"

[api]
  dashboard = true

[log]
  filePath = "/traefik.log"

[experimental.plugins.crowdsec-bouncer-traefik-plugin]
  moduleName = "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
  version = "v1.7.1"

[experimental.plugins.other]
  moduleName = "github.com/example/other"
  version = "v1.7.1"
`;

const TOML_LOCAL = `[entryPoints.traefik]
  address = ":8080"

[api]
  dashboard = true
  insecure = true

[experimental.localPlugins.crowdsec-bouncer-traefik-plugin]
  moduleName = "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin"
`;

const YAML_STATIC = `experimental:
  plugins:
    bouncer:
      moduleName: github.com/example/bouncer
      version: v1.2.3
    other:
      moduleName: github.com/example/other
      version: v1.2.3
`;

function plugin(name: string, moduleName: string): PluginDecl {
  return { name, moduleName, version: null, mode: "local", source: "file" };
}

function rel(tag: string): Release {
  return { tag, url: `u/${tag}`, version: parseVersion(tag)! };
}

// --- versions and tags ------------------------------------------------------

Deno.test("parseVersion reads v-prefixed and short versions, rejects tags", () => {
  assertEquals(parseVersion("v3.7.16"), {
    major: 3,
    minor: 7,
    patch: 16,
    prerelease: null,
  });
  assertEquals(parseVersion("3.7")?.patch, 0);
  assertEquals(parseVersion("v1.8.1-rc.1")?.prerelease, "rc.1");
  assertEquals(parseVersion("latest"), null);
  assertEquals(parseVersion("sha256:abc"), null);
});

Deno.test("parseTag: a variant suffix is not a prerelease", () => {
  const t = parseTag("v1.6.3-debian")!;
  assertEquals(t.version.prerelease, null);
  assertEquals(t.variant, "-debian");
  const rc = parseTag("v1.8.0-rc.1-alpine")!;
  assertEquals([rc.version.prerelease, rc.variant], ["rc.1", "-alpine"]);
  assertEquals(parseTag("v3.7")!.precision, 2);
  assertEquals(parseTag("3")!.precision, 1);
});

Deno.test("review 1.1: a -debian pin is current at its own release, and keeps its variant", () => {
  assertEquals(
    statusOf("v1.6.3-debian", parseVersion("v1.6.3")).status,
    "current",
  );
  assertEquals(formatLike("v1.6.3-debian", "v1.6.4"), "v1.6.4-debian");
  assertEquals(formatLike("1.6.3-alpine", "v1.6.4"), "1.6.4-alpine");
});

Deno.test("compareVersions sorts a prerelease below its release", () => {
  const v = (s: string) => parseVersion(s)!;
  assert(compareVersions(v("3.7.9"), v("3.7.16")) < 0);
  assert(compareVersions(v("3.8.0-rc.1"), v("3.8.0")) < 0);
  assertEquals(compareVersions(v("v1.8.1"), v("1.8.1")), 0);
});

Deno.test("formatLike keeps the pin's v-prefix convention", () => {
  assertEquals(formatLike("v3.7.9", "3.7.16"), "v3.7.16");
  assertEquals(formatLike("3.7.9", "v3.7.16"), "3.7.16");
});

Deno.test("chooseTarget stays in the pinned major and reports the next one", () => {
  const rels = ["v4.0.1", "v3.7.16", "v3.7.15", "v2.11.30"].map(rel);
  const up = chooseTarget(rels, parseVersion("v3.7.9"));
  assertEquals(up.target?.tag, "v3.7.16");
  assertEquals(up.newerMajor, "v4.0.1");
  assertEquals(
    chooseTarget(rels, parseVersion("v2.11.1")).target?.tag,
    "v2.11.30",
  );
});

Deno.test("review 2.6: allowPrerelease actually changes the target", () => {
  const rels = ["v3.8.0-rc.1", "v3.7.16"].map(rel);
  assertEquals(
    chooseTarget(rels, parseVersion("v3.7.9")).target?.tag,
    "v3.7.16",
  );
  assertEquals(
    chooseTarget(rels, parseVersion("v3.7.9"), true).target?.tag,
    "v3.8.0-rc.1",
  );
});

Deno.test("statusOf: unknown is never current, and says why", () => {
  for (
    const [pin, target] of [
      [null, "1.0.0"],
      ["latest", "1.0.0"],
      ["v1.0.0", null],
    ] as const
  ) {
    const s = statusOf(pin, target ? parseVersion(target) : null);
    assertEquals(s.status, "unknown");
    assert(s.reason);
  }
  assertEquals(statusOf("v1.0.0", parseVersion("1.0.1")).status, "behind");
  assertEquals(statusOf("v1.2.0", parseVersion("1.0.1")).status, "ahead");
});

Deno.test("review 1.10: a floating tag is unknown, not behind", () => {
  const s = statusOf("v3", parseVersion("v3.7.16"));
  assertEquals(s.status, "unknown");
  assertStringIncludes(s.reason!, "floating");
  assertEquals(statusOf("v3.7", parseVersion("v3.7.16")).status, "unknown");
});

// --- image references -------------------------------------------------------

Deno.test("parseImageRef normalises Docker Hub forms", () => {
  for (
    const raw of [
      "traefik:v3",
      "library/traefik:v3",
      "docker.io/library/traefik:v3",
    ]
  ) {
    const r = parseImageRef(raw)!;
    assertEquals([r.registry, r.repository, r.tag], [
      "docker.io",
      "traefik",
      "v3",
    ]);
  }
  const g = parseImageRef("ghcr.io/owner/img:1.2@sha256:abc")!;
  assertEquals([g.registry, g.repository, g.tag, g.digest], [
    "ghcr.io",
    "owner/img",
    "1.2",
    "sha256:abc",
  ]);
  assertEquals(parseImageRef("localhost:5000/x:1")?.registry, "localhost:5000");
  assertEquals(parseImageRef("${IMAGE}"), null);
  assertEquals(parseImageRef("traefik:$TAG"), null);
});

Deno.test("registryCoordinates maps official images to library/", () => {
  assertEquals(registryCoordinates(parseImageRef("traefik:v3")!), {
    host: "registry-1.docker.io",
    repository: "library/traefik",
  });
});

// --- configuration ----------------------------------------------------------

Deno.test("composeImages separates parseable images from variable ones", () => {
  const doc = parseCompose(
    "c.yml",
    COMPOSE_FILE_CONFIG + "  side:\n    image: ${SIDE_IMAGE}\n",
  );
  const { images, unresolved } = composeImages("c.yml", doc);
  assertEquals(
    images.map((i) => `${i.service}=${i.ref.repository}:${i.ref.tag}`),
    ["traefik=traefik:v3.7.9", "crowdsec=crowdsecurity/crowdsec:v1.7.4"],
  );
  assertEquals(unresolved.map((u) => u.service), ["side"]);
});

Deno.test("CLI flags are recognised and parsed for plugins", () => {
  const args = serviceCommand(
    parseCompose("c.yml", COMPOSE_CLI_CONFIG),
    "traefik",
  );
  assert(hasConfigFlags(args));
  assertFalse(hasConfigFlags(["--configFile=/etc/traefik/traefik.yml"]));
  const s = staticFromCli(args);
  assert(s.apiInsecure);
  assertEquals(s.plugins.map((p) => `${p.name}@${p.version}:${p.mode}`), [
    "crowdsec-bouncer-traefik-plugin@v1.7.1:remote",
    "Fail2Ban@v0.8.9:remote",
  ]);
});

Deno.test("review 2.5: quoted and capitalised CLI values", () => {
  const s = staticFromCli([
    "--api.insecure=True",
    `--entrypoints.traefik.address=":9000"`,
  ]);
  assert(s.apiInsecure);
  assertEquals(s.apiEntrypointPort, 9000);
});

Deno.test("static TOML: remote and local plugins, log file, API port", () => {
  const r = staticFromDocument(parseStaticFile("t.toml", TOML_REMOTE));
  assertEquals(r.plugins.length, 2);
  assert(r.plugins.every((p) => p.mode === "remote" && p.version === "v1.7.1"));
  assertEquals(r.logFilePath, "/traefik.log");
  const l = staticFromDocument(parseStaticFile("t.toml", TOML_LOCAL));
  assertEquals(l.plugins[0].mode, "local");
  assertEquals(l.apiEntrypointPort, 8080);
  assert(l.apiInsecure);
});

Deno.test("publishesPort: published API vs loopback-only, ranges, host network", () => {
  const doc = parseCompose("c.yml", COMPOSE_CLI_CONFIG);
  assert(publishesPort(doc, "traefik", 8080));
  assertFalse(publishesPort(doc, "traefik", 9000));
  const y = (s: string) => parseCompose("c.yml", `services:\n  traefik:\n${s}`);
  assertFalse(
    publishesPort(
      y(`    ports:\n      - "127.0.0.1:8080:8080"\n`),
      "traefik",
      8080,
    ),
  );
  assert(
    publishesPort(
      y(`    ports:\n      - target: 8080\n        published: 8080\n`),
      "traefik",
      8080,
    ),
  );
  assert(
    publishesPort(
      y(`    ports:\n      - "8000-8100:8000-8100"\n`),
      "traefik",
      8080,
    ),
  );
  assert(publishesPort(y(`    network_mode: host\n`), "traefik", 8080));
});

Deno.test("githubRepoOfModule", () => {
  assertEquals(
    githubRepoOfModule("github.com/tomMoulard/fail2ban"),
    "tomMoulard/fail2ban",
  );
  assertEquals(githubRepoOfModule("github.com/a/b/sub/pkg"), "a/b");
  assertEquals(githubRepoOfModule("gitlab.com/a/b"), null);
});

// --- the vendoring record -----------------------------------------------------

const BOUNCER = plugin("bouncer", "github.com/example/bouncer");
const GEO = plugin("geoblock", "github.com/example/geoblock");
const NEW_HASHES = {
  version: "v1.4.3",
  commit: "e".repeat(40),
  sha256: "f".repeat(64),
};

Deno.test("vendoredVersionFromRecord reads the version from the plugin's section", () => {
  const record =
    "# Vendored\n\n## crowdsec-bouncer-traefik-plugin v1.7.1\n\n- tag `v1.7.1`\n\n## Upgrading\nV=v1.7.2 # example\n";
  const p = plugin(
    "crowdsec-bouncer-traefik-plugin",
    "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin",
  );
  assertEquals(vendoredVersionFromRecord(record, p), "v1.7.1");
  assertEquals(vendoredVersionFromRecord("nothing here", p), null);
});

Deno.test("review 1.3: a two-plugin record is edited only in the bumped plugin's section", () => {
  const a = "a".repeat(40);
  const b = "b".repeat(64);
  const c = "c".repeat(40);
  const d = "d".repeat(64);
  const record =
    `- bouncer v1.4.2 commit ${a} sha256 ${b}\n- geoblock v1.4.2 commit ${c} sha256 ${d}\n`;
  const out = updateVendorRecord(
    record,
    GEO,
    [BOUNCER, GEO],
    "v1.4.2",
    NEW_HASHES,
  )!;
  assertEquals(
    out,
    `- bouncer v1.4.2 commit ${a} sha256 ${b}\n- geoblock v1.4.3 commit ${
      "e".repeat(40)
    } sha256 ${"f".repeat(64)}\n`,
  );
  assertEquals(
    vendoredVersionFromRecord(out, BOUNCER, [BOUNCER, GEO]),
    "v1.4.2",
  );
  assertEquals(vendoredVersionFromRecord(out, GEO, [BOUNCER, GEO]), "v1.4.3");
});

Deno.test("review 1.4: a version ending a sentence is still updated", () => {
  const out = updateVendorRecord(
    "Vendored bouncer at v1.4.2.\n",
    BOUNCER,
    [BOUNCER],
    "v1.4.2",
    NEW_HASHES,
  );
  assertEquals(out, "Vendored bouncer at v1.4.3.\n");
  assertEquals(
    vendoredVersionFromRecord("Vendored bouncer at v1.4.2.", BOUNCER),
    "v1.4.2",
  );
});

Deno.test("review 1.4: a record that cannot be updated returns null, not the same text", () => {
  assertEquals(
    updateVendorRecord(
      "bouncer, version unknown\n",
      BOUNCER,
      [BOUNCER],
      "v1.4.2",
      NEW_HASHES,
    ),
    null,
  );
});

Deno.test("updateVendorRecord leaves a nearby different version alone", () => {
  const record = "## bouncer v1.7.1\n- tag `v1.7.1`, see v1.7.10 notes\n";
  const out = updateVendorRecord(record, BOUNCER, [BOUNCER], "v1.7.1", {
    ...NEW_HASHES,
    version: "v1.8.1",
  })!;
  assertStringIncludes(out, "## bouncer v1.8.1");
  assertStringIncludes(out, "v1.7.10 notes");
});

Deno.test("recordSection ends at the next heading", () => {
  assertEquals(
    recordSection("## bouncer v1\nx\n## Upgrading\ny\n", BOUNCER, [BOUNCER]),
    { start: 0, end: 2 },
  );
});

// --- edits ------------------------------------------------------------------

Deno.test("editImageTag changes only the tag, keeping quotes and comments", () => {
  const e = editImageTag(COMPOSE_FILE_CONFIG, "traefik", "v3.7.9", "v3.7.16");
  assertEquals(e.changes.length, 1);
  assertEquals(
    e.changes[0].after,
    "    image: 'traefik:v3.7.16'   # edge proxy",
  );
  assertStringIncludes(e.text, 'image: "crowdsecurity/crowdsec:v1.7.4"');
  assertEquals(
    editImageTag(e.text, "traefik", "v3.7.9", "v3.7.16").changes.length,
    0,
  );
});

Deno.test("review 1.2: a second service on another major is not retagged", () => {
  const text =
    "services:\n  edge:\n    image: traefik:v3.7.9\n  legacy:\n    image: traefik:v2.11.0\n";
  const e = editImageTag(text, "traefik", "v3.7.9", "v3.7.16");
  assertEquals(e.changes.length, 1);
  assertStringIncludes(e.text, "image: traefik:v2.11.0");
});

Deno.test("editImageTag drops a stale digest", () => {
  const e = editImageTag(
    "    image: traefik:v3.7.9@sha256:abc\n",
    "traefik",
    "v3.7.9",
    "v3.7.16",
  );
  assertEquals(e.changes[0].after, "    image: traefik:v3.7.16");
});

Deno.test("editPluginVersion: TOML edits only the named plugin's table", () => {
  const e = editPluginVersion(
    TOML_REMOTE,
    "traefik.toml",
    "crowdsec-bouncer-traefik-plugin",
    "v1.8.1",
  );
  assertEquals(e.changes.length, 1);
  assertEquals(e.changes[0].after, '  version = "v1.8.1"');
  assertStringIncludes(
    e.text,
    '[experimental.plugins.other]\n  moduleName = "github.com/example/other"\n  version = "v1.7.1"',
  );
});

Deno.test("editPluginVersion: CLI flag in a compose command", () => {
  const e = editPluginVersion(
    COMPOSE_CLI_CONFIG,
    "docker-compose.yml",
    "Fail2Ban",
    "v0.9.0",
  );
  assertEquals(e.changes.length, 1);
  assertStringIncludes(e.changes[0].after, "Fail2Ban.version=v0.9.0");
  assertStringIncludes(
    e.text,
    "crowdsec-bouncer-traefik-plugin.version=v1.7.1",
  );
});

Deno.test("editPluginVersion: YAML map, by indentation", () => {
  const e = editPluginVersion(YAML_STATIC, "traefik.yml", "bouncer", "v1.3.0");
  assertEquals(e.changes.length, 1);
  assertEquals(e.changes[0].line, 5);
  assertStringIncludes(
    e.text,
    "other:\n      moduleName: github.com/example/other\n      version: v1.2.3",
  );
});

Deno.test("allowCatalogTestData marks key-like lines once", () => {
  const src =
    "testData:\n  CrowdsecLapiKey: abc\n  enabled: true\n  apiToken: x # gitleaks:allow\n";
  const out = allowCatalogTestData(src);
  assertStringIncludes(out, "CrowdsecLapiKey: abc # gitleaks:allow");
  assertEquals(out.match(/gitleaks:allow/g)?.length, 2);
});

Deno.test("allowCatalogTestData keeps a previous hand-written annotation", () => {
  const prev =
    "testData:\n  ApiKey: abc  # gitleaks:allow -- catalog test value\n";
  assertEquals(
    allowCatalogTestData("testData:\n  ApiKey: abc\n  NewKey: def\n", prev),
    "testData:\n  ApiKey: abc  # gitleaks:allow -- catalog test value\n  NewKey: def # gitleaks:allow\n",
  );
});

Deno.test("selectVendorFiles keeps runtime code, drops tests/examples, names new files", () => {
  const paths = [
    ".traefik.yml",
    "LICENSE",
    "go.mod",
    "go.sum",
    "bouncer.go",
    "bouncer_test.go",
    "ban.html",
    "README.md",
    "new-asset.html",
    "pkg/cache/cache.go",
    "pkg/cache/cache_test.go",
    "pkg/cache/testdata/x.json",
    "vendor/modules.txt",
    "vendor/github.com/x/y/y.go",
    "examples/main.go",
    ".github/workflows/ci.yml",
  ];
  const { keep, skippedNew } = selectVendorFiles(paths, new Set(["ban.html"]));
  assertEquals(keep, [
    ".traefik.yml",
    "LICENSE",
    "ban.html",
    "bouncer.go",
    "go.mod",
    "go.sum",
    "pkg/cache/cache.go",
    "vendor/github.com/x/y/y.go",
    "vendor/modules.txt",
  ]);
  assertEquals(skippedNew, ["README.md", "new-asset.html"]);
});

Deno.test("review 1.5: a previously vendored subdirectory asset is kept; nested examples are not", () => {
  const { keep, skippedNew } = selectVendorFiles(
    [
      "x.go",
      ".traefik.yml",
      "templates/ban.html",
      "templates/new.html",
      "pkg/a.go",
      "pkg/examples/main.go",
    ],
    new Set(["templates/ban.html"]),
  );
  assert(keep.includes("templates/ban.html"));
  assertFalse(keep.includes("pkg/examples/main.go"));
  assert(skippedNew.includes("templates/new.html"));
});

Deno.test("gitBlobSha matches git hash-object", async () => {
  assertEquals(
    await gitBlobSha(new TextEncoder().encode("hello\n")),
    "ce013625030ba8dba906f756967f9e9ca394464a",
  );
});

Deno.test("review 1.11: refPath keeps slashes in branch names", () => {
  assertEquals(refPath("release/v3"), "release/v3");
  assertEquals(refPath("a b/c"), "a%20b/c");
});

// --- PRs ------------------------------------------------------------------

const PULLS = [
  {
    number: 19,
    url: "u19",
    title: "chore(deps): bump traefik from v3.7.9 to v3.7.15",
    head: "dependabot/docker_compose/traefik-v3.7.15",
    author: "app/dependabot",
  },
  {
    number: 17,
    url: "u17",
    title: "chore(deps): bump crowdsecurity/crowdsec from v1.7.4 to v1.8.1",
    head: "dependabot/x",
    author: "app/dependabot",
  },
];

Deno.test("relatedPrs: a Dependabot PR at the target is pending, short of it superseded", () => {
  const t = { kind: "image" as const, name: "traefik" };
  assertEquals(
    relatedPrs(PULLS, t, parseVersion("v3.7.15")).pending.map((p) => p.number),
    [19],
  );
  const r = relatedPrs(PULLS, t, parseVersion("v3.7.16"));
  assertEquals([r.pending.length, r.superseded.map((p) => p.number)], [0, [
    19,
  ]]);
  assertEquals(
    relatedPrs(
      PULLS,
      { kind: "image", name: "crowdsecurity/crowdsec" },
      parseVersion("1.8.1"),
    ).pending.map((p) => p.number),
    [17],
  );
});

Deno.test("review 1.6: own-branch matching is exact and version-aware", () => {
  const mk = (head: string) => [{
    number: 3,
    url: "u3",
    title: "x",
    head,
    author: "app",
  }];
  const traefik = { kind: "image" as const, name: "traefik" };
  const other = relatedPrs(
    mk("swamp-traefik/plugin-geoblock-ext-v1.0.1"),
    { kind: "plugin", name: "geoblock" },
    parseVersion("v1.0.1"),
  );
  assertEquals([other.pending.length, other.superseded.length], [0, 0]);
  const stale = relatedPrs(
    mk("swamp-traefik/image-traefik-v3.7.10"),
    traefik,
    parseVersion("v3.7.16"),
  );
  assertEquals([stale.pending.length, stale.superseded.length], [0, 1]);
  const same = relatedPrs(
    mk("swamp-traefik/image-traefik-v3.7.16"),
    traefik,
    parseVersion("v3.7.16"),
  );
  assertEquals(same.pending.length, 1);
});

// --- the live read ----------------------------------------------------------

Deno.test("liveScript runs only read-only docker subcommands", () => {
  const s = liveScript("traefik", 8080, "/traefik.log");
  for (const line of s.split("\n").filter((l) => l.startsWith("docker"))) {
    assert(/^docker (inspect|exec|logs) /.test(line), line);
  }
  assertFalse(
    /\b(rm|stop|kill|restart|start|pull|compose|cp)\b/.test(
      s.split("\n").filter((l) => l.includes("docker")).map((l) =>
        l.replace(/docker (inspect|exec|logs)/, "")
      ).join("\n"),
    ),
  );
  assertFalse(s.includes(".Config.Env"));
  assertFalse(s.includes("{{json .}}"));
  assertFalse(s.includes("Labels"));
});

Deno.test("liveScript refuses anything but validated values", () => {
  for (const bad of ["x; rm -rf /", "-it", "a b", "$(id)"]) {
    let threw = false;
    try {
      liveScript(bad, 8080, null);
    } catch {
      threw = true;
    }
    assert(threw, bad);
  }
  let threw = false;
  try {
    liveScript("traefik", 8080, "/x; id");
  } catch {
    threw = true;
  }
  assert(threw);
});

Deno.test("liveScript marks unreadable log sources instead of reading them as clean", () => {
  const s = liveScript("traefik", null, "/traefik.log");
  assertStringIncludes(s, 'test -r "/traefik.log" || echo "@@NOFILE"');
  assertStringIncludes(s, '|| echo "@@NOLOGS"');
});

Deno.test("every section marker is preceded by a newline", () => {
  const script = liveScript("traefik", 8080, null);
  assert(
    script.split("\n").filter((l) => /echo "@@(?!FAIL|NO)/.test(l)).every(
      (l) => l.startsWith('echo; echo "@@'),
    ),
  );
  const s = splitSections(
    '@@INSPECT\n{}\n\n@@API version\n{"a":1}\n@@API overview\n{"b":2}\n@@END\n',
  );
  assertEquals(s.get("API version"), '{"a":1}');
  assertEquals(s.get("API overview"), '{"b":2}');
});

Deno.test("remoteCommand carries the script base64-encoded, nothing on stdin", () => {
  assert(
    /^echo [A-Za-z0-9+/=]+ \| base64 -d \| sh$/.test(
      remoteCommand("echo hi\n"),
    ),
  );
});

Deno.test("sshArgs keeps host key checking and batch mode on", () => {
  const a = sshArgs("proxy.example", "ops", "true");
  assert(a.includes("StrictHostKeyChecking=accept-new"));
  assert(a.includes("BatchMode=yes"));
  assertEquals(a.at(-2), "ops@proxy.example");
});

Deno.test("parseMiddlewares never carries a plugin's configuration or error text", () => {
  const rows = parseMiddlewares([{
    name: "crowdsec-bouncer@file",
    type: "crowdsec-bouncer-traefik-plugin",
    status: "disabled",
    provider: "file",
    error: ["bad config: crowdsecLapiKey=SECRET"],
    plugin: {
      "crowdsec-bouncer-traefik-plugin": { crowdsecLapiKey: "SECRET" },
    },
  }]);
  assertFalse(JSON.stringify(rows).includes("SECRET"));
  assert(rows[0].isPlugin);
});

Deno.test("review 3.1: a partial API read is described, never quoted", () => {
  const partial =
    '[{"plugin":{"bouncer":{"crowdsecLapiKey":"SUPERSECRETLAPIKEY0123"}}';
  const d = describeApiFailure(
    partial + "\nwget: error getting response\n@@FAIL",
  );
  assertFalse(d.includes("SUPERSECRET"));
  assertStringIncludes(d, "withheld");
  assertEquals(
    describeApiFailure(
      "wget: can't connect to remote host (127.0.0.1): Connection refused\n@@FAIL",
    ),
    "wget: can't connect to remote host (127.0.0.1): Connection refused",
  );
});

Deno.test("logLineTime reads default and JSON formats", () => {
  assertEquals(
    logLineTime("2025-03-14T09:26:53Z ERR Plugins are disabled")
      ?.toISOString(),
    "2025-03-14T09:26:53.000Z",
  );
  assertEquals(
    logLineTime('{"level":"error","time":"2025-03-14T09:26:53Z","message":"x"}')
      ?.toISOString(),
    "2025-03-14T09:26:53.000Z",
  );
  assertEquals(logLineTime("no time here"), null);
});

Deno.test("resolveLogFile resolves a relative filePath against Traefik's cwd", () => {
  assertEquals(resolveLogFile("traefik.log"), "/traefik.log");
  assertEquals(resolveLogFile("./logs/t.log"), "/logs/t.log");
  assertEquals(resolveLogFile("/var/log/traefik.log"), "/var/log/traefik.log");
  assertEquals(resolveLogFile("../etc/x"), null);
  assertEquals(resolveLogFile("a b.log"), null);
  assertEquals(resolveLogFile(null), null);
});

const INSPECT =
  '{"image":"traefik:v3.7.13","status":"running","startedAt":"2026-10-20T00:00:00Z","restartCount":0}';

function apiMap(over: Record<string, string> = {}) {
  return new Map<string, string | null>(Object.entries({
    "version": '{"Version":"3.7.13"}',
    "overview": '{"http":{"routers":{"total":2,"warnings":0,"errors":0}}}',
    "http/routers?per_page=1000":
      '[{"name":"a@docker","status":"enabled","provider":"docker"},{"name":"b@docker","status":"enabled","provider":"docker"}]',
    "tcp/routers?per_page=1000": "[]",
    "udp/routers?per_page=1000": "[]",
    "http/middlewares?per_page=1000":
      '[{"name":"cs@file","type":"bouncer","status":"enabled","provider":"file","plugin":{"bouncer":{"key":"x"}}}]',
    ...over,
  }));
}

function runtimeWith(over: Partial<Parameters<typeof buildRuntime>[0]> = {}) {
  return buildRuntime({
    host: "proxy",
    container: "traefik",
    inspectJson: INSPECT,
    versionText: "Version:      3.7.13\nCodename:     x",
    api: apiMap(),
    apiVia: "container",
    apiError: null,
    logLines: [],
    ...over,
  });
}

Deno.test("buildRuntime: a healthy proxy", () => {
  const r = runtimeWith();
  assertEquals(r.healthy, true);
  assertEquals(r.version, "3.7.13");
  assertEquals([r.routers.total, r.routers.enabled], [2, 2]);
  assertEquals(r.middlewares.plugin.map((m) => m.name), ["cs@file"]);
});

Deno.test("buildRuntime: TCP routers count too", () => {
  const r = runtimeWith({
    api: apiMap({
      "tcp/routers?per_page=1000":
        '[{"name":"db@file","status":"disabled","provider":"file"}]',
    }),
  });
  assertEquals(
    r.routers.notEnabled.map((x) => `${x.name}/${x.protocol}`),
    ["db@file/tcp"],
  );
  assertEquals(r.healthy, false);
});

Deno.test("buildRuntime: a plugin failure from before this start is ignored", () => {
  const r = runtimeWith({
    logLines: [
      "2025-03-14T09:26:53Z ERR Plugins are disabled because an error has occurred",
    ],
  });
  assertFalse(r.pluginsDisabled);
  assertEquals(r.healthy, true);
});

Deno.test("buildRuntime: a plugin failure since this start is critical", () => {
  const r = runtimeWith({
    logLines: [
      "2026-10-20T00:00:03Z ERR Plugins are disabled because an error has occurred",
    ],
  });
  assert(r.pluginsDisabled);
  assertEquals(r.healthy, false);
});

Deno.test("review 2.2: an unreachable API makes healthy null, not true", () => {
  const r = runtimeWith({
    api: new Map(),
    apiVia: "none",
    apiError: "connection refused",
  });
  assertFalse(r.routersChecked);
  assertEquals(r.healthy, null);
});

Deno.test("review 2.2: a disabled plugin middleware is unhealthy", () => {
  const r = runtimeWith({
    api: apiMap({
      "http/middlewares?per_page=1000":
        '[{"name":"cs@file","type":"bouncer","status":"disabled","provider":"file","plugin":{}}]',
    }),
  });
  assertEquals(r.healthy, false);
  assertEquals(r.middlewares.notEnabled.length, 1);
});

Deno.test("review 2.4: unreadable docker logs with no log file is not healthy", () => {
  assertEquals(runtimeWith({ containerLogsReadable: false }).healthy, null);
  assertEquals(
    runtimeWith({
      containerLogsReadable: false,
      logFile: { path: "/traefik.log", readable: true },
    }).healthy,
    true,
  );
});

Deno.test("buildRuntime: garbage from docker inspect throws without quoting it", () => {
  let msg = "";
  try {
    runtimeWith({ inspectJson: "Error: No such object: traefik SECRETISH" });
  } catch (e) {
    msg = (e as Error).message;
  }
  assert(msg);
  assertFalse(msg.includes("SECRETISH"));
});

// --- findings ---------------------------------------------------------------

function component(over: Record<string, unknown> = {}) {
  return {
    id: "image:traefik",
    kind: "image" as const,
    name: "traefik",
    mode: null,
    file: "c",
    upstream: "traefik/traefik",
    pinned: "v3.6.9",
    otherPins: [] as string[],
    running: "3.7.13",
    latest: "v3.7.16",
    latestUrl: null,
    newerMajor: null,
    status: "behind" as const,
    reason: null,
    change: "minor" as const,
    imageAvailable: true,
    pendingPrs: [],
    supersededPrs: [],
    ...over,
  } as Parameters<typeof computeFindings>[1][number];
}

Deno.test("computeFindings orders critical first and flags the exposure", () => {
  const settings = staticFromCli(
    serviceCommand(parseCompose("c", COMPOSE_CLI_CONFIG), "traefik"),
  );
  const findings = computeFindings(
    {
      settings,
      apiPublished: true,
      shadowedStaticFile: "traefik/traefik.toml",
      configSource: "cli",
    },
    [component()],
    runtimeWith({
      logLines: ["2026-10-20T00:00:03Z ERR Plugins are disabled"],
    }),
  );
  const codes = findings.map((f) => f.code);
  assertEquals(codes[0], "plugins-disabled");
  for (
    const c of [
      "remote-plugin",
      "insecure-api-published",
      "static-config-shadowed",
      "undeployed",
      "behind",
    ]
  ) assert(codes.includes(c), c);
  assertEquals(codes.filter((c) => c === "remote-plugin").length, 2);
});

Deno.test("computeFindings: a clean deployment has none", () => {
  const settings = staticFromDocument(parseStaticFile("t.toml", TOML_LOCAL));
  assertEquals(
    computeFindings(
      {
        settings,
        apiPublished: false,
        shadowedStaticFile: null,
        configSource: "file",
      },
      [],
      runtimeWith(),
    ),
    [],
  );
});

Deno.test("review 2.1: unknown versions, unresolved images and no static config are findings", () => {
  const codes = computeFindings(
    {
      settings: {
        apiInsecure: false,
        logFilePath: null,
        apiEntrypointPort: 8080,
        plugins: [],
      },
      apiPublished: false,
      shadowedStaticFile: null,
      configSource: "unknown",
      staticNote: "mounted from outside",
      unresolved: [{ file: "c", service: "side", raw: "${X}" }],
    },
    [
      component({
        status: "unknown",
        change: null,
        reason: "floating",
        pinned: "v3",
      }),
    ],
    null,
  ).map((f) => f.code);
  for (
    const c of ["version-unknown", "image-unresolved", "static-config-unknown"]
  ) assert(codes.includes(c), c);
});

Deno.test("computeFindings: mixed pins and blind spots are named", () => {
  const settings = staticFromDocument(parseStaticFile("t.toml", TOML_LOCAL));
  const codes = computeFindings(
    {
      settings,
      apiPublished: false,
      shadowedStaticFile: null,
      configSource: "file",
    },
    [
      component({
        status: "current",
        change: null,
        pinned: "v3.7.13",
        otherPins: ["v2.11.0"],
      }),
    ],
    runtimeWith({
      logFile: { path: "/traefik.log", readable: false },
      api: new Map(),
      apiVia: "none",
      apiError: "x",
    }),
  ).map((f) => f.code);
  for (const c of ["mixed-pins", "log-file-unreadable", "api-unreachable"]) {
    assert(codes.includes(c), c);
  }
});

// --- the model surface ------------------------------------------------------

Deno.test("the type exposes inspect, check and bump", () => {
  assertEquals(Object.keys(model.methods), ["inspect", "check", "bump"]);
});

Deno.test("bump is dry-run by default and refuses risk by default", () => {
  const args = model.methods.bump.arguments.parse({});
  assertEquals(args.dryRun, true);
  assertEquals(args.allowMajor, false);
  assertEquals(args.allowRemotePlugins, false);
  assertEquals(args.component, "all");
});

Deno.test("githubToken is marked sensitive; apiUrl refuses embedded credentials", () => {
  const meta = model.globalArguments.shape.githubToken.unwrap().meta() as
    | { sensitive?: boolean }
    | undefined;
  assertEquals(meta?.sensitive, true);
  assertFalse(
    model.globalArguments.shape.apiUrl.safeParse("http://user:pass@proxy:8080")
      .success,
  );
  assert(
    model.globalArguments.shape.apiUrl.safeParse("http://proxy:8080").success,
  );
});

Deno.test("releases(): stops paging once the pin is reached; tokens go only to their own side", async () => {
  const calls: { url: string; auth: string | null }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const auth = new Headers(init?.headers).get("authorization");
    calls.push({ url, auth });
    const body = url.includes("/releases")
      ? JSON.stringify(
        Array.from({ length: 100 }, (_, i) => ({
          tag_name: `v3.7.${120 - i}`,
          html_url: "u",
        })),
      )
      : JSON.stringify([]);
    return Promise.resolve(new Response(body, { status: 200 }));
  }) as typeof fetch;
  try {
    const gh = new GitHub(
      "https://api.example",
      "DEPLOY",
      1000,
      undefined,
      "UPSTREAM",
    );
    const rels = await gh.releases("traefik/traefik", parseVersion("v3.7.30"));
    assertEquals(rels[0].tag, "v3.7.120");
    assertEquals(calls.length, 1);
    assertEquals(calls[0].auth, "Bearer UPSTREAM");
    assert(calls[0].url.startsWith("https://api.github.com/"));
    await gh.openPulls("me/deploy", "main");
    assertEquals(calls[1].auth, "Bearer DEPLOY");
    assert(calls[1].url.startsWith("https://api.example/"));
    assert(calls[1].url.includes("base=main"));
    const anon = new GitHub("https://api.example", "DEPLOY", 1000);
    await anon.releases("x/y");
    assertEquals(calls[2].auth, null);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// --- second review round ----------------------------------------------------

Deno.test("N1: release candidates compare numerically (rc.10 > rc.9)", () => {
  const rels = ["v3.8.0-rc.9", "v3.8.0-rc.10", "v3.7.16"].map(rel)
    .sort((a, b) => compareVersions(b.version, a.version));
  assertEquals(rels[0].tag, "v3.8.0-rc.10");
  assertEquals(
    chooseTarget(rels, parseVersion("v3.7.9"), true).target?.tag,
    "v3.8.0-rc.10",
  );
});

Deno.test("N3: -next/-canary pins are prereleases, not the final release", () => {
  assertEquals(parseVersion("v1.0.0-next.1")?.prerelease, "next.1");
  assertEquals(parseVersion("v1.0.0-canary")?.prerelease, "canary");
  assertEquals(
    statusOf("v1.0.0-next.1", parseVersion("v1.0.0")).status,
    "behind",
  );
});

Deno.test("N3: a branch is ours only when its suffix is exactly a version", () => {
  const r = relatedPrs(
    [{
      number: 4,
      url: "u",
      title: "x",
      head: "swamp-traefik/plugin-foo-1-v1.2.3",
      author: "a",
    }],
    { kind: "plugin", name: "foo" },
    parseVersion("v1.0.0"),
  );
  assertEquals([r.pending.length, r.superseded.length], [0, 0]);
});

Deno.test("N3: GitHub's prerelease flag wins over a plain tag", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(
        JSON.stringify([
          { tag_name: "v3.8.0", html_url: "u", prerelease: true },
          { tag_name: "v3.7.16", html_url: "u", prerelease: false },
        ]),
        { status: 200 },
      ),
    )) as typeof fetch;
  try {
    const rels = await new GitHub("https://api.example", undefined, 1000)
      .releases("traefik/traefik");
    assertEquals(
      chooseTarget(rels, parseVersion("v3.7.9")).target?.tag,
      "v3.7.16",
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

Deno.test("N4: missing TCP/UDP endpoints do not discard the HTTP check", () => {
  const api = apiMap();
  api.delete("tcp/routers?per_page=1000");
  api.delete("udp/routers?per_page=1000");
  const r = runtimeWith({ api });
  assert(r.routersChecked);
  assertEquals(r.healthy, true);
});

Deno.test("N6: an intro line naming every plugin does not swallow the sections", () => {
  const record =
    "Vendored: bouncer and geoblock.\n\n## bouncer v1.4.2\n- x\n\n## geoblock v2.0.1\n- y\n";
  assertEquals(
    vendoredVersionFromRecord(record, BOUNCER, [BOUNCER, GEO]),
    "v1.4.2",
  );
  assertEquals(
    vendoredVersionFromRecord(record, GEO, [BOUNCER, GEO]),
    "v2.0.1",
  );
});

Deno.test("1.10: a floating Traefik pin raises version-unknown, not undeployed", () => {
  const settings = staticFromDocument(parseStaticFile("t.toml", TOML_LOCAL));
  const codes = computeFindings(
    {
      settings,
      apiPublished: false,
      shadowedStaticFile: null,
      configSource: "file",
    },
    [component({
      pinned: "v3",
      status: "unknown",
      change: null,
      reason: "floating",
    })],
    runtimeWith(),
  ).map((f) => f.code);
  assert(codes.includes("version-unknown"));
  assertFalse(codes.includes("undeployed"));
});

Deno.test("3.2: no middleware's error text is kept (basicAuth can quote a hash)", () => {
  const rows = parseMiddlewares([{
    name: "auth@file",
    type: "basicauth",
    status: "disabled",
    provider: "file",
    error: ["error parsing BasicUser: u:$apr1$SECRETHASH"],
  }]);
  assertFalse(JSON.stringify(rows).includes("SECRETHASH"));
  assertEquals(rows[0].status, "disabled");
});

// --- third review round -----------------------------------------------------

const repoFiles = (paths: string[]) => (p: string) =>
  Promise.resolve(paths.includes(p));

Deno.test("R3.1: a static file where Traefik looks wins over flags", async () => {
  const doc = parseCompose(
    "docker-compose.yaml",
    `services:
  traefik:
    image: traefik:v3.7.5
    command: ["--log.level=INFO"]
    volumes:
      - ./data/traefik.yml:/traefik.yml:ro
      - ./data/dynamic:/etc/traefik/dynamic:ro
`,
  );
  const args = serviceCommand(doc, "traefik");
  const loc = await locateStaticFile(
    staticCandidates(args),
    serviceMounts(doc, "traefik", ""),
    repoFiles(["data/traefik.yml"]),
  );
  assertEquals(loc, {
    kind: "file",
    repoPath: "data/traefik.yml",
    containerPath: "/traefik.yml",
  });
  assert(hasConfigFlags(args)); // present, and ignored by Traefik
});

Deno.test("R3.1: a repo mounted elsewhere leaves flags in charge", async () => {
  const doc = parseCompose(
    "traefik/docker-compose.yml",
    `services:
  traefik:
    image: traefik:v3.6.9
    command: ["--providers.docker=true"]
    volumes:
      - ./:/app:ro
`,
  );
  const loc = await locateStaticFile(
    staticCandidates(serviceCommand(doc, "traefik")),
    serviceMounts(doc, "traefik", "traefik"),
    repoFiles(["traefik/traefik.toml"]),
  );
  assertEquals(loc.kind, "absent");
});

Deno.test("R3.1: --configFile is honoured in both spellings", async () => {
  assertEquals(configFileFlag(["--configFile=/conf/t.toml"]), "/conf/t.toml");
  assertEquals(
    configFileFlag(["--configfile", "/conf/t.toml"]),
    "/conf/t.toml",
  );
  const doc = parseCompose(
    "c.yml",
    `services:
  traefik:
    image: traefik:v3.7.5
    command: ["--configFile=/conf/t.toml"]
    volumes: ["./conf:/conf:ro"]
`,
  );
  const loc = await locateStaticFile(
    staticCandidates(serviceCommand(doc, "traefik")),
    serviceMounts(doc, "traefik", ""),
    repoFiles(["conf/t.toml"]),
  );
  assertEquals(loc.kind === "file" && loc.repoPath, "conf/t.toml");
});

Deno.test("R3.1: a mount the repo does not describe makes the source unknown", async () => {
  for (
    const volumes of [
      `["/opt/traefik/traefik.toml:/etc/traefik/traefik.toml"]`,
      `["traefik-conf:/etc/traefik"]`,
      `["./missing.toml:/traefik.toml"]`,
    ]
  ) {
    const doc = parseCompose(
      "c.yml",
      `services:\n  traefik:\n    image: traefik:v3\n    volumes: ${volumes}\n`,
    );
    const loc = await locateStaticFile(
      staticCandidates([]),
      serviceMounts(doc, "traefik", ""),
      repoFiles([]),
    );
    assertEquals(loc.kind, "external", volumes);
  }
});

Deno.test("R3.3: static file keys match case-insensitively, read and edit", () => {
  const toml = `[Experimental.Plugins.bouncer]
  modulename = "github.com/x/bouncer"
  Version = "v1.0.0"
`;
  const s = staticFromDocument(parseStaticFile("t.toml", toml));
  assertEquals(s.plugins.map((p) => `${p.name}@${p.version}`), [
    "bouncer@v1.0.0",
  ]);
  const e = editPluginVersion(toml, "t.toml", "bouncer", "v1.1.0");
  assertEquals(e.changes.length, 1);
  assertStringIncludes(e.text, `Version = "v1.1.0"`);
  const yaml = `experimental:
  Plugins:
    bouncer:
      moduleName: github.com/x/bouncer
      VERSION: v1.0.0
`;
  assertEquals(
    staticFromDocument(parseStaticFile("t.yml", yaml)).plugins[0].version,
    "v1.0.0",
  );
  assertEquals(
    editPluginVersion(yaml, "t.yml", "bouncer", "v1.1.0").changes.length,
    1,
  );
});

Deno.test("R3.4: only a dependency bot's title, from the current pin, holds a bump", () => {
  const t = { kind: "image" as const, name: "traefik" };
  const pr = (author: string, from: string) => ({
    number: 9,
    url: "u",
    title: `Bump traefik from ${from} to v99.0.0`,
    head: "x",
    author,
  });
  const pin = parseVersion("v3.7.9");
  const target = parseVersion("v3.7.16");
  assertEquals(
    relatedPrs([pr("stranger", "v3.7.9")], t, target, pin).pending,
    [],
  );
  assertEquals(
    relatedPrs([pr("dependabot[bot]", "v3.6.0")], t, target, pin).pending,
    [],
  );
  assertEquals(
    relatedPrs([pr("dependabot[bot]", "v3.7.9")], t, target, pin).pending
      .length,
    1,
  );
});

Deno.test("R3.5/R3.9: only Traefik's own records count as plugin failures", () => {
  const forged = [
    `203.0.113.9 - - [20/Oct/2026:00:00:05 +0000] "GET / HTTP/1.1" 404 19 "-" "Plugins are disabled <evil>" 1`,
    `{"ClientAddr":"x","level":"info","msg":"","request_User-Agent":"Plugins are disabled"}`,
    `2026-10-20T00:00:05Z INF access Plugins are disabled`,
  ];
  for (const l of forged) assertEquals(pluginsDisabledRecord(l), null, l);
  const coloured =
    "\x1b[90m2026-10-20T00:00:05Z\x1b[0m \x1b[31mERR\x1b[0m \x1b[1mgithub.com/traefik/traefik/v3/cmd/traefik/traefik.go:1\x1b[0m\x1b[36m >\x1b[0m Plugins are disabled because an error has occurred.";
  assertEquals(
    pluginsDisabledRecord(coloured)?.time?.toISOString(),
    "2026-10-20T00:00:05.000Z",
  );
  assertEquals(
    pluginsDisabledRecord(
      `time="2020-01-01T00:00:00Z" level=error msg="Plugins are disabled because x"`,
    )?.time?.toISOString(),
    "2020-01-01T00:00:00.000Z",
  );
  assertEquals(
    pluginsDisabledRecord(
      `{"level":"error","time":"2026-10-20T00:00:05Z","message":"Plugins are disabled because x"}`,
    )?.time?.toISOString(),
    "2026-10-20T00:00:05.000Z",
  );
  const r = runtimeWith({ logLines: forged });
  assertFalse(r.pluginsDisabled);
  const stale = runtimeWith({
    logLines: [
      `time="2020-01-01T00:00:00Z" level=error msg="Plugins are disabled because x"`,
    ],
  });
  assertFalse(stale.pluginsDisabled);
});

Deno.test("R3.8: a container port published on a random host port counts", () => {
  const doc = (ports: string) =>
    parseCompose(
      "c.yml",
      `services:\n  traefik:\n    image: traefik:v3\n    ports: ${ports}\n`,
    );
  assert(publishesPort(doc(`["8080"]`), "traefik", 8080));
  assert(publishesPort(doc(`[{target: 8080}]`), "traefik", 8080));
  assertFalse(publishesPort(doc(`["127.0.0.1::8080"]`), "traefik", 8080));
  assertFalse(
    publishesPort(doc(`[{target: 8080, host_ip: 127.0.0.1}]`), "traefik", 8080),
  );
});

Deno.test("R3.16: a version inside a longer prerelease string is left alone", () => {
  const plugin = {
    name: "bouncer",
    moduleName: "github.com/x/bouncer",
    version: null,
    mode: "local" as const,
    source: "file" as const,
  };
  const out = updateVendorRecord(
    "## bouncer\nVendored v1.2.3 (tested v1.2.3-rc.1)\n",
    plugin,
    [plugin],
    "v1.2.3",
    { version: "v1.2.4", commit: "c".repeat(40), sha256: "d".repeat(64) },
  );
  assertStringIncludes(out!, "Vendored v1.2.4 (tested v1.2.3-rc.1)");
});

/** One 512-byte ustar header. */
function tarHeader(name: string, type: string, size: number): Uint8Array {
  const h = new Uint8Array(512);
  const put = (off: number, str: string) =>
    h.set(new TextEncoder().encode(str), off);
  put(0, name);
  put(100, "0000644\0");
  put(108, "0000000\0");
  put(116, "0000000\0");
  put(124, size.toString(8).padStart(11, "0") + "\0");
  put(136, "00000000000\0");
  put(156, type);
  put(257, "ustar\0");
  put(263, "00");
  put(148, "        ");
  const sum = h.reduce((a, b) => a + b, 0);
  put(148, sum.toString(8).padStart(6, "0") + "\0 ");
  return h;
}

async function gzipTar(parts: Uint8Array[]): Promise<Uint8Array> {
  const stream = new Blob(
    [...parts, new Uint8Array(1024)].map((x) => new Uint8Array(x)),
  ).stream()
    .pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

Deno.test("R3.17: a tarball with long-path pax headers is refused", async () => {
  const body = new TextEncoder().encode("30 path=x/very/long/name.go\n");
  const block = new Uint8Array(512);
  block.set(body);
  const bad = await gzipTar([
    tarHeader("x/PaxHeaders/1", "x", body.length),
    block,
    tarHeader("x/abc.data", "0", 0),
  ]);
  let threw = false;
  try {
    await extractTarball(bad);
  } catch {
    threw = true;
  }
  assert(threw);
  const ok = await gzipTar([tarHeader("x/a.go", "0", 0)]);
  assertEquals([...(await extractTarball(ok)).keys()], ["a.go"]);
});

Deno.test("R3.11: plugin releases include tags published without a release", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = String(input);
    const body = url.includes("/releases")
      ? [{ tag_name: "v1.2.0", html_url: "u" }]
      : [{ name: "v1.3.0" }, { name: "v1.2.0" }];
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
  }) as typeof fetch;
  try {
    const gh = new GitHub("https://api.example", undefined, 1000);
    assertEquals(
      (await gh.releases("x/plugin", null, { tags: true }))[0].tag,
      "v1.3.0",
    );
    assertEquals((await gh.releases("x/plugin"))[0].tag, "v1.2.0");
  } finally {
    globalThis.fetch = realFetch;
  }
});

Deno.test("R3.13: githubApiUrl must be https", () => {
  const schema = model.globalArguments;
  assertFalse(
    schema.safeParse({ sshHost: "h", githubApiUrl: "http://api.example" })
      .success,
  );
  assert(
    schema.safeParse({ sshHost: "h", githubApiUrl: "https://api.example" })
      .success,
  );
});

Deno.test("R3: flags in `--key value` form are read", () => {
  const s = staticFromCli([
    "--experimental.plugins.geo.modulename",
    "github.com/x/geo",
    "--experimental.plugins.geo.version",
    "v0.3.1",
    "--api.insecure",
  ]);
  assertEquals(s.plugins.map((p) => `${p.name}@${p.version}`), ["geo@v0.3.1"]);
  assert(s.apiInsecure);
});

Deno.test("R3 truncation: a full page of routers leaves health unchecked", () => {
  const routers = Array.from({ length: 1000 }, (_, i) => ({
    name: `r${i}@docker`,
    status: "enabled",
    provider: "docker",
  }));
  const r = runtimeWith({
    api: apiMap({ "http/routers?per_page=1000": JSON.stringify(routers) }),
  });
  assert(r.listsTruncated);
  assertFalse(r.routersChecked);
  assertEquals(r.healthy, null);
  assertEquals(runtimeWith().listsTruncated, false);
  assertEquals(runtimeWith().repoReadError, null);
});

Deno.test("R3 truncation: more than 1000 open PRs is an error, not a guess", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(
        JSON.stringify(
          Array.from({ length: 100 }, (_, i) => ({
            number: i,
            html_url: "u",
            title: "t",
            head: { ref: "b", repo: { full_name: "me/deploy" } },
            user: { login: "a" },
          })),
        ),
        { status: 200 },
      ),
    )) as typeof fetch;
  try {
    let threw = false;
    try {
      await new GitHub("https://api.example", "T", 1000).openPulls(
        "me/deploy",
        "main",
      );
    } catch {
      threw = true;
    }
    assert(threw);
  } finally {
    globalThis.fetch = realFetch;
  }
});

Deno.test("R3.2: bump refuses when the static configuration source is unknown", async () => {
  const c = component({ latestUrl: "https://example.org/r" });
  const base = {
    component: c.id,
    from: c.pinned,
    to: null,
    status: "refused" as const,
    reason: null,
    branch: null,
    prUrl: null,
    files: [],
    notes: [],
  };
  const args = { dryRun: true, allowMajor: false, allowRemotePlugins: false };
  // deno-lint-ignore no-explicit-any
  const desired = { configSource: "unknown" } as any;
  let err: unknown = null;
  try {
    // deno-lint-ignore no-explicit-any
    await bumpOne({} as any, {} as any, desired, c, args, [], [], base);
  } catch (e) {
    err = e;
  }
  assert(err instanceof Refusal);
  assertStringIncludes((err as Error).message, "unknown");
});

Deno.test("R3.12/R3.14: PR body flags a 0.x minor and never names the host", () => {
  const c = component({ kind: "plugin", name: "geo", pinned: "v0.8.9" });
  const body = prBody(
    // deno-lint-ignore no-explicit-any
    { sshHost: "proxy.internal.example" } as any,
    c,
    parseVersion("v0.8.9")!,
    "v0.9.0",
    parseVersion("v0.9.0")!,
    null,
    [],
    [],
    [],
  );
  assertStringIncludes(body, "Pre-1.0 minor");
  assertFalse(body.includes("proxy.internal.example"));
  const patch = prBody(
    // deno-lint-ignore no-explicit-any
    {} as any,
    c,
    parseVersion("v0.8.9")!,
    "v0.8.10",
    parseVersion("v0.8.10")!,
    null,
    [],
    [],
    [],
  );
  assertFalse(patch.includes("Pre-1.0 minor"));
});
