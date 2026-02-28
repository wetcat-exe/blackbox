# Blackbox

Automated security reconnaissance and triage assistant powered by ChatGPT.

## What it does

- Performs lightweight recon checks on web targets:
  - Missing security headers
  - Risky CORS configuration
  - Potentially weak cookie flags (`HttpOnly`, `Secure`, `SameSite`)
  - Potential server version disclosure
  - Interesting `robots.txt` entries
  - Exposed sensitive paths (`/.env`, `/.git/`, backups, etc.)
  - HTTP (non-TLS) usage and short TLS certificate lifetime warnings
- Sends findings to ChatGPT for triage and report generation.
- Produces machine-readable JSON and a markdown report.
- Scans multiple targets concurrently.

## Quick start

```bash
python bugbounty_tool.py --target example.com
```

Use multiple targets:

```bash
python bugbounty_tool.py --target example.com --target api.example.com
```

Or read from a file:

```bash
python bugbounty_tool.py --targets-file targets.txt
```

## Useful options

```bash
python bugbounty_tool.py \
  --targets-file targets.txt \
  --max-workers 12 \
  --timeout 8 \
  --user-agent "Blackbox/2.1"
```

Outputs are written to `reports/` by default:

- `reports/scan_results.json`
- `reports/triage_report.md`

## ChatGPT integration

Set your OpenAI API key:

```bash
export OPENAI_API_KEY="your_api_key_here"
```

Optional model override:

```bash
python bugbounty_tool.py --target example.com --model gpt-4o-mini
```

If no API key is set (or the API is unreachable), the tool automatically falls back to local severity-based ranking with a severity summary section.


## Roadmap

See the state-of-the-art roadmap and implementation checklist in [`STATE_OF_THE_ART_CHECKLIST.md`](STATE_OF_THE_ART_CHECKLIST.md).

## Ethical use

Only scan assets you are explicitly authorized to test.
