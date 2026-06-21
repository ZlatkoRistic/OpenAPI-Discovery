# API Discovery & OpenAPI Generation Tool

A hybrid black-box API discovery tool that combines wordlist fuzzing (**ffuf**),
optional headless-browser crawling (**Katana**), JavaScript/HTML mining, path-parameter
inference, and parameter-name fuzzing into a single pipeline that outputs a ready-to-use
**OpenAPI 3.0 specification**.

It is designed for the situation where you have a running REST API (your own, or one
you are authorized to test) and need to reconstruct its surface — including endpoints
that are never linked anywhere in the frontend.

> ⚠️ **Authorized use only.** This tool actively sends fuzzing traffic (potentially
> hundreds of thousands of requests) to the target. Only run it against systems you own
> or have explicit written permission to test.

---

## What it does

| Stage | Tool | Finds |
|---|---|---|
| Crawl | Katana (optional) | Linked endpoints, SPA routes, XHR/fetch calls, form submissions — requires the app to actually expose a path through its UI |
| Bruteforce | ffuf | Endpoints that are **never linked anywhere** — admin routes, backup paths, undocumented APIs |
| Mine | Regex over HTML/JS | `fetch()`, `axios`, `$.ajax`, `url_for()` / Jinja2 / Twig / Django template routes |
| Probe | Baseline-diff prober | Hidden path parameters — `/users/{id}`, `/items/{uuid}`, `/profile/{slug}` |
| Fuzz | ffuf (parameter mode) | Query and body parameter names for every discovered endpoint |
| Export | Internal generator | A complete OpenAPI 3.0 spec (`.yaml` or `.json`) |

Because ffuf and Katana cover different blind spots (see [Why both ffuf and
Katana](#why-both-ffuf-and-katana) below), running them together produces meaningfully
more complete results than either alone.

---

## Requirements

### Python

- Python 3.9+
- See [`requirements.txt`](#installation) — only `requests` and `PyYAML`

### External tools (Go binaries, not pip packages)

| Tool | Required for | Install |
|---|---|---|
| [ffuf](https://github.com/ffuf/ffuf) | Wordlist bruteforcing (`-f`, `--smart-chain`, `--chain-wordlists`) | `go install github.com/ffuf/ffuf/v2@latest` or `brew install ffuf` |
| [Katana](https://github.com/projectdiscovery/katana) | Crawling (`--katana`, `--headless`, `--katana-only`) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| Chrome / Chromium | Headless crawling (`--headless`) | Any recent Chrome/Chromium install; Katana auto-detects it |

The tool degrades gracefully — if `ffuf` or `katana` are missing, it prints a clear
message and skips that phase rather than crashing.

---

## Installation

```bash
git clone https://github.com/ZlatkoRistic/OpenAPI-Discovery.git
cd OpenAPI-Discovery

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Install ffuf (required for wordlist fuzzing)
go install github.com/ffuf/ffuf/v2@latest

# Install Katana (optional, required for --katana / --headless)
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Make sure `$GOPATH/bin` (typically `~/go/bin`) is on your `PATH` so `ffuf` and `katana`
are callable directly.

---

## Quick start

```bash
python3 api_discovery.py \
  -t http://127.0.0.1:5000 \
  -w wordlists/masterlist.txt \
  --smart-chain \
  --katana \
  --methods GET POST PUT DELETE \
  --param-wordlist wordlists/burp-parameter-names.txt \
  --openapi openapi_spec.yaml \
  -o results.txt \
  -j results.json \
  -od ./output
```

This runs the full hybrid pipeline: Katana crawl → root HTML/JS mining → ffuf wordlist
bruteforce → iterative response analysis → path-parameter probing → parameter-name
fuzzing → OpenAPI export.

---

## Usage modes

The tool has four independent modes, selected by which flags you pass.

### 1. `--smart-chain` (recommended)

The full hybrid pipeline described above. Works with a wordlist alone, Katana alone, or
both together.

```bash
# ffuf only (no Katana installed / not wanted)
python3 api_discovery.py -t http://target -w wordlist.txt --smart-chain

# Katana (standard, no JS execution) + ffuf
python3 api_discovery.py -t http://target -w wordlist.txt --smart-chain --katana

# Katana headless (executes JS, follows SPA routes) + ffuf
python3 api_discovery.py -t http://target -w wordlist.txt --smart-chain --headless

# Katana only, no wordlist bruteforce at all
python3 api_discovery.py -t http://target --smart-chain --katana-only --headless

# Authenticated crawl — pass your session cookie to Katana
python3 api_discovery.py -t http://target -w wordlist.txt --smart-chain --headless \
  --katana-cookie "session=eyJhbGc..."
```

### 2. `-f` / `--fuzz` (simple ffuf-only mode)

Runs ffuf once (optionally across multiple `--methods`), then a JS-mining pass and
path-parameter probing on top of whatever it found. No iterative response analysis.

```bash
python3 api_discovery.py -t http://target -w wordlist.txt -f --methods GET POST
```

### 3. `--chain-wordlists` (sequential wordlist chaining)

Runs multiple wordlists in sequence, using endpoints found by one as a base path for
fuzzing the next — useful for nested resource discovery (`/api/` → `/api/users/` →
`/api/users/admin/`).

```bash
python3 api_discovery.py -t http://target \
  --chain-wordlists common.txt api.txt admin.txt --recursive 2
```

### 4. `-d` / `-a` (offline analysis)

Analyze existing ffuf JSON output directories or local HTML files without making any
new requests.

```bash
python3 api_discovery.py -d ./ffuf_results_dir -a ./html_files -o results.txt
```

---

## Full CLI reference

### Target & fuzzing basics

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | — | Target API base URL, e.g. `http://127.0.0.1:5000` |
| `-w`, `--wordlist` | — | Wordlist file for ffuf bruteforcing |
| `-f`, `--fuzz` | off | Run ffuf-only fuzzing mode |
| `--threads` | `40` | ffuf thread budget (divided across methods when run concurrently) |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--retry` | `2` | Retries for timed-out fetch requests before giving up |
| `-mc`, `--match-codes` | `200,201,401,403` | HTTP status codes considered a "hit" |
| `--methods` | `GET POST` | HTTP methods to fuzz with (space-separated) |
| `--no-follow-redirects` | off | Disable following HTTP redirects |

### Output

| Flag | Default | Description |
|---|---|---|
| `-od`, `--output-dir` | `./fuzzing_results` | Directory for raw ffuf/Katana output |
| `--output-file` | `ffuf_results.json` | Filename for raw ffuf JSON |
| `-o`, `--output` | `api_discovery_results.txt` | Final human-readable results file |
| `-j`, `--json` | — | Final results as JSON |
| `--openapi` | — | OpenAPI spec output path (`.yaml` or `.json` — format inferred from extension) |
| `--api-title` | `Discovered API` | Title field in the generated OpenAPI spec |
| `--api-version` | `1.0.0` | Version field in the generated OpenAPI spec |

### Chained wordlist fuzzing

| Flag | Default | Description |
|---|---|---|
| `--chain-wordlists` | — | One or more wordlists to run in sequence (space-separated) |
| `--recursive` | `1` | Recursion depth for endpoints discovered mid-chain |

### Smart chain discovery

| Flag | Default | Description |
|---|---|---|
| `--smart-chain` | off | Enable the full hybrid discovery pipeline |
| `--max-iterations` | `3` | Max response-analysis iterations before stopping |
| `--discover-params` | off | *(legacy flag, kept for compatibility — path-param probing now always runs)* |

### Parameter discovery

| Flag | Default | Description |
|---|---|---|
| `--param-wordlist` | — | Wordlist of parameter names; enables query/body fuzzing on every endpoint |
| `--param-fuzz-workers` | `8` | Concurrent ffuf processes during parameter fuzzing |
| `--no-path-params` | off | Skip baseline-diff path-parameter probing (`/endpoint/{id}`) |

### JS mining

| Flag | Default | Description |
|---|---|---|
| `--js-workers` | `10` | Concurrent workers for fetching `<script src>` JS files |

### Katana integration

| Flag | Default | Description |
|---|---|---|
| `--katana` | off | Enable Katana crawl alongside ffuf (standard mode, no JS execution) |
| `--headless` | off | Run Katana with headless Chromium (executes JS, follows SPA routes, intercepts XHR) |
| `--katana-depth` | `5` | Katana crawl depth |
| `--katana-cookie` | — | Cookie header for authenticated crawling, e.g. `"session=abc123"` |
| `--katana-only` | off | Use Katana exclusively, skip ffuf bruteforcing entirely |

### Offline analysis

| Flag | Default | Description |
|---|---|---|
| `-d`, `--dirs` | — | Analyze one or more existing ffuf result directories |
| `-a`, `--analyze-html` | — | Analyze HTML files in a directory for embedded endpoint references (default `.` if flag given with no value) |

---

## Output files

Running with `--smart-chain` and full export flags produces:

```
output/
├── smart_discovery_results.txt     # human-readable endpoint list (raw discovery phase)
├── smart_discovery_results.json    # same, as JSON
├── katana_output.jsonl             # raw Katana crawl records (if --katana/--headless used)
├── ffuf_results_get.json           # raw ffuf output per method
├── ffuf_results_post.json
├── params_<method>_<endpoint>.json # raw ffuf output per parameter-fuzzing run
results.txt                          # final combined, deduplicated results
results.json                         # same, as JSON
openapi_spec.yaml                    # generated OpenAPI 3.0 specification
```

