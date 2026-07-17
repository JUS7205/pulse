# pulse

A blue-team host telemetry tripwire. `pulse` captures a point-in-time snapshot of
a host's **process tree** and **IPv4 TCP connection table**, then diffs a later
snapshot against a baseline to surface drift:

- **new processes** — processes present now but not at baseline
- **new external connections** — off-host connections that appeared since baseline
- **orphaned parents** — processes whose parent changed or disappeared (reparenting /
  spawn-after-parent-exit)

A pure verdict classifier turns that drift into `OK` / `WARN` / `ALERT`.

This is the **blue-team continuous-monitoring** facet of the
*runtime defense of autonomous systems* project spine.

## Install

```sh
cargo install --path .
# or build locally
cargo build --release
```

## Usage

```sh
# Capture a fresh snapshot of this host and print it as JSON.
pulse snapshot > baseline.json

# ... time passes / something happens ...

pulse snapshot > current.json

# Compute drift between the two snapshots.
pulse diff baseline.json current.json

# Classify the drift. Flags any watched PID whose children spawn.
pulse verdict baseline.json current.json --watch 880
```

`pulse verdict` exits `0` for `OK`/`WARN` and `1` for `ALERT`, so it drops
straight into a cron/CI monitor.

## Library

```rust
use pulse::snapshot::{capture, is_public, Snapshot};
use pulse::watch::{diff, baseline};
use pulse::verdict::{classify, Config, Verdict};

let base = baseline();          // == capture()
let cur = capture();
let d = diff(&base, &cur);
let v = classify(&d, &base, &cur, &Config::default());
println!("{:?}", v.tag());      // "OK" | "WARN" | "ALERT"
```

The diff and verdict logic is platform-independent and fully unit-tested; only
the `snapshot` collection backend differs per OS (see status table).

## Verdict rules

| Condition                                                        | Verdict |
| ---------------------------------------------------------------- | ------- |
| Any new external connection to a **public** (non-RFC1918) IP     | ALERT   |
| New process that is a child of a **watched** PID                 | WARN    |
| Any reparented / orphaned parent                                 | WARN    |
| Otherwise (no notable drift)                                     | OK      |

ALERT takes precedence over WARN.

## Status

| Capability                                  | Windows            | Linux / macOS        |
| ------------------------------------------- | ------------------ | -------------------- |
| Process tree enumeration                    | ✅ Toolhelp snapshot | ⚠️ returns empty (no data fabricated) |
| IPv4 TCP connection table (PID-attributed)  | ✅ `GetExtendedTcpTable` | ⚠️ returns empty (no data fabricated) |
| `pulse snapshot` (JSON)                     | ✅ live host data  | ⚠️ honest empty snapshot |
| `pulse diff A.json B.json`                  | ✅                  | ✅ (pure, platform-independent) |
| `pulse verdict` classification             | ✅                  | ✅ (pure, platform-independent) |
| Unit + integration tests                   | ✅ 20 passing      | ✅ 20 passing        |

> **Honest note:** On non-Windows targets the collection backend does **not**
> fabricate process or connection data — it returns an empty snapshot. The
> diff/verdict engine still builds and is fully tested against the committed
> sample snapshots under `examples/`. Real collection backends for Unix
> (`/proc`, `netstat`/`/proc/net/tcp`) are a planned follow-up, not yet
> implemented.

## Sample data

`examples/` ships a baseline + current pair (plus `sample.snapshot.json`) used by
the integration tests and suitable for a quick demo without touching a live host:

```sh
pulse diff examples/baseline.json examples/current.json
pulse verdict examples/baseline.json examples/current.json
```

## Implemented against Win32 directly

`pulse` uses the same user-mode Win32 primitives an EDR / anti-cheat engine uses:

- `CreateToolhelp32Snapshot` + `Process32First`/`Process32Next` for the process tree
- `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` for PID-attributed sockets

The small FFI is copied locally (no dependency on the sibling `sentinel` crate).

## Tests

```sh
cargo test        # 17 unit tests (snapshot / watch / verdict) + 3 CLI integration tests
```

## License

MIT
