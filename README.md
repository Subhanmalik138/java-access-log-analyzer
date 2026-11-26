# LogLens — Access Log Analyzer CLI

A zero-dependency Java 17 CLI that turns Apache/Nginx access logs into a
readable traffic report: status breakdowns, top paths and IPs, error rate,
bot traffic, hourly patterns, and slow-request percentiles.

## The problem

Raw access logs are the cheapest observability a web server has, but reading
them means grepping thousands of lines by hand. LogLens answers the questions
you actually ask after an incident — *what broke, who hit it, was it a bot,
and what was slow* — in one pass, without loading the whole file into memory.

## Features

- **Common and Combined log formats**, auto-detected per line, plus an
  optional trailing request-time field (Nginx `$request_time`).
- **Status, method and byte statistics** — per-code counts, 2xx/3xx/4xx/5xx
  classes, error rate, total and average bytes served.
- **Top-N lists** — paths by requests, paths by bytes, client IPs, bot families.
- **Bot detection** — user-agent heuristics covering the common crawlers
  (Googlebot, Bingbot, Baiduspider, Ahrefs, Semrush, …).
- **Hourly histogram** — requests per hour of day, for spotting traffic spikes.
- **Slow requests** — p50/p95/p99 of request times plus a slowest-requests
  list, when the log carries timings.
- **Filtering** — `--status`, `--method`, `--since`, `--until` narrow the
  analysis before aggregation, so filtered-out lines cost nothing.
- **Text or JSON output** (`--json`) for piping into other tools or CI.
- **Strict by default, tolerant on request** — a malformed line aborts with
  its line number; `--tolerant` skips bad lines and reports them.

## Design decisions

1. **One regex per format, named groups.** A hand-rolled character scanner
   would be marginally faster, but log analysis is I/O-bound and the regex
   is far easier to audit against the Apache log-format spec.
2. **Streaming aggregation.** Lines are read one at a time and only the
   aggregated counters are kept. A 10 GB log uses the same memory as a
   10 KB one (modulo distinct paths/IPs, which top-N reporting needs).
3. **Filters applied at ingest.** `--since`/`--status`/etc. are checked in
   `LogAnalyzer.accept`, before any map is touched — filtering is free.
4. **No dependencies, not even for JSON.** The report JSON is escaped by
   hand; pulling in a JSON library for one small object would be bloat.
   Tests use JUnit 5 (console-standalone jar, fetched by `build.sh`).

## Usage

```bash
./build.sh            # compile, produces out/loglens.jar
./build.sh test       # compile + run the JUnit suite

java -jar out/loglens.jar examples/sample-access.log
java -jar out/loglens.jar /var/log/nginx/access.log --top 20 --json
java -jar out/loglens.jar access.log --status 404,500 --since 2026-11-26T00:00:00+05:00
cat access.log | java -jar out/loglens.jar - --tolerant
```

```
Access log report
=================
Requests analysed: 12
Bytes served:      89,832 (avg 7,486 / request)
Error rate:        25.00% (4xx + 5xx)
Bot requests:      2 (16.67%)

Status codes
------------
  200  7
  201  1
  301  1
  403  1
  404  1
  500  1
...
```

Exit codes: `0` success, `1` usage error, `2` unreadable input or a
malformed line in strict mode.

## Options

| Flag | Meaning |
| ---- | ------- |
| `--top N` | Top-N list size (default 10) |
| `--status CODES` | Only these statuses, e.g. `404,500` |
| `--method METHODS` | Only these methods, e.g. `GET,POST` |
| `--since ISO` | Only entries at/after this instant |
| `--until ISO` | Only entries at/before this instant |
| `--format FMT` | `common` \| `combined` \| `auto` (default `auto`) |
| `--json` | Emit JSON instead of the text report |
| `--tolerant` | Skip malformed lines instead of aborting |

## Running the tests

```bash
./build.sh test
```

34 JUnit 5 tests cover the parser (both formats, malformed lines, IPv6,
request-time field), the analyzer (status classes, top-N ordering, bot
grouping, percentiles, filters), the JSON escaping, and the CLI end to end
(strict/tolerant modes, exit codes, output shapes).

## Tech stack

- Java 17, zero runtime dependencies
- JUnit 5 (test only)
- `bash` build script — `javac` + `jar`, no build tool required

## License

MIT — see [LICENSE](LICENSE).
