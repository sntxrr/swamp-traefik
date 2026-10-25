# swamp-traefik

A [swamp](https://github.com/systeminit/swamp) extension that keeps Traefik
reverse proxies, their sidecar images and every plugin they load up to date,
through pull requests to the repository each proxy is deployed from.

**The full documentation is [`extensions/models/README.md`](extensions/models/README.md)**,
which is also what ships with the extension.

## Install

```bash
swamp extension pull @sntxrr/traefik
```

## Development

```bash
~/.swamp/deno/deno check extensions/models/traefik.ts
~/.swamp/deno/deno lint extensions/models/
~/.swamp/deno/deno test extensions/models/
```
