# sonar-cli

`sonar-cli` is a headless Sonar/Marmot command-line client for agents and
automation. It uses the same `sonar-core` engine as the app shells and prints
newline-delimited JSON so another process, such as a Hermes Agent, can consume
messages without linking to Sonar internals.

## Quick Start

```bash
cargo run -p sonar-cli -- init
cargo run -p sonar-cli -- publish
cargo run -p sonar-cli -- send --to npub1... --text "hello"
cargo run -p sonar-cli -- listen
```

Use `--home <dir>` or `SONAR_CLI_HOME` to isolate an agent identity. The CLI
stores `config.json`, the encrypted Marmot database, and the seen-message cursor
under that directory. On Unix, directories are written as `0700` and JSON secret
files as `0600`.

To import an existing agent identity, prefer `init --nsec-file <path>` or
`init --nsec-env <VAR>` over `--nsec`, because command-line arguments are often
captured in shell history and process listings.

## Sticker Packs

`post` imports a Signal sticker pack, uploads the plaintext sticker images to a
Blossom server, publishes a Sonar `kind:30030` sticker-pack event to the
configured relays, and prints JSON with the website URL:

```bash
cargo run -p sonar-cli -- post 'https://signal.art/addstickers/#pack_id=...&pack_key=...'
```

Options:

- `--blossom <https-url>`: Blossom server for uploaded sticker images. Defaults
  to Sonar's media fallback server.
- `--site-url <https-url>`: stickers page used in the returned link. Defaults
  to `SONAR_STICKERS_SITE_URL` or the bundled `/stickers` web route.
- `--accept-invalid-signal-certs`: fetch encrypted Signal CDN blobs even when
  local TLS interception breaks certificate validation. The decrypted sticker
  data is still authenticated by Signal's pack-key HMAC before publishing.
- `--skip-missing-signal-stickers`: publish the pack with the importable
  stickers when the Signal manifest references an unavailable asset. Skipped
  Signal ids are reported in the JSON output.

The Signal `pack_key` is only used locally for decryption and is never included
in the published Nostr event.

## Agent Contract

Every command prints newline-delimited JSON. The `type` field identifies the
record: `identity`, `published`, `sent`, `message`, `group`, or
`posted_sticker_pack`. The full command surface:

| Command | Purpose |
| --- | --- |
| `init [--nsec-file p \| --nsec-env VAR \| --nsec s] [--force]` | Provision/replace the identity. |
| `identity` | Print `{npub, pubkey_hex, home, config_path}`. |
| `publish` | Publish the Marmot KeyPackage so peers can DM the agent. |
| `send --to <npub\|hex> --text <s> [--group-name <s>]` | Send a direct message (find/create the 1:1 group). |
| `listen [--once] [--timeout-secs n] [--poll-secs n] [--no-publish]` | Drain inbound messages as JSON lines. |
| `groups` | List known Marmot groups `{id, name, members[]}`. |
| `messages [--group <hex>]` | Print message history (includes the agent's own `mine:true` rows). |
| `post <signal-link> [...]` | Import + publish a Signal sticker pack. |

`listen` emits one JSON object per inbound message:

```json
{"type":"message","group_id":"...","id":"...","sender":"npub1...","content":"...","created_at_secs":123,"mine":false}
```

The command records seen message IDs before exiting, so rerunning `listen` only
emits new messages, and it never emits the agent's own messages (`mine` is
filtered out). A bare `listen` streams until interrupted; `listen --once`
performs a single sync/drain cycle, which is what cron-style agents and tests
should use. `send` is direct-message only (it targets an npub), and transport is
Nostr-relay only — the CLI does not drive BLE mesh.

## Notifications

`listen` can alert an operator in near-real-time when a new message arrives,
so a headless agent does not require anyone to poll a UI:

```bash
cargo run -p sonar-cli -- listen --once --notify-command 'notify-send "Sonar" "$SONAR_CONTENT"'
```

`--notify-command <cmd>` runs the command through the platform shell
(`sh -c` on Unix, `cmd /C` on Windows) once per newly-drained inbound message,
injecting these environment variables:

| Variable | Meaning |
| --- | --- |
| `SONAR_MSG_ID` | Message id (Nostr event id hex). |
| `SONAR_SENDER` | Sender npub. |
| `SONAR_GROUP_ID` | Marmot group id hex. |
| `SONAR_GROUP_NAME` | Group name (may be empty). |
| `SONAR_CONTENT` | Plaintext message body. |
| `SONAR_CREATED_AT` | Message timestamp, unix seconds. |

The command is best-effort: a non-zero exit or spawn failure is reported on
stderr and never aborts the listen loop. It runs synchronously per message so a
cron `listen --once` cycle finishes its alert before the process exits — keep
the command short, or background it inside the shell (`... &`) for a long-lived
listener.

HTTP/webhook alerting needs no special flag — point the command at `curl`:

```bash
cargo run -p sonar-cli -- listen --once \
  --notify-command 'curl -s -X POST https://ntfy.example/topic -d "$SONAR_CONTENT"'
```

If the command embeds a secret (e.g. a bearer token), read it from an
environment variable inside the shell rather than putting it on the command
line — shell history and process listings capture `--notify-command` just like
any other argument.

> This is a *local* alert relay, not the MIP-05/transponder push system that
> wakes the iOS/Android apps. A headless process has no APNs/FCM device token,
> so it cannot receive those pushes directly; `--notify-command` is the
> agent-side equivalent. The CLI's `send` already emits the transponder wakeup
> for app-using peers via the shared `sonar-core` send path.

To run this as an autonomous Hermes agent (terminal toolset + cron-polled
`listen --once`), see [`docs/HERMES-AGENT.md`](../../docs/HERMES-AGENT.md) and
the bundled skill at [`hermes/SKILL.md`](hermes/SKILL.md).
