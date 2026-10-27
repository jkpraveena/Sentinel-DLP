# Sentinel DLP — AI-Assisted Egress Proxy

An educational, local-first implementation for a cybersecurity DLP practical. It demonstrates:
- Regex-based detection for Luhn-valid card-like numbers and explicitly labelled 12-digit IDs.
- Ambiguous 12-digit values routed to optional local AI verification.
- Dynamic redaction and conservative fail-safe handling.
- An HTTP proxy endpoint that blocks uploads to non-allowlisted destinations with `403 Forbidden`.
- A simple browser dashboard and command-line demo.
- Basic SSRF protections and request-size limits.

> **Scope:** This is a classroom prototype, not a production DLP gateway. It does not intercept all traffic from your laptop, decrypt HTTPS, inspect every binary file format, or replace endpoint security. Use only synthetic test data. Review the security notes below before any real deployment.

## Requirements

- macOS, Windows, or Linux
- Python 3.10+
- Internet connection only for installing Python dependencies (not needed for local AI after the model is downloaded)
- Optional: [Ollama](https://ollama.com) for local semantic classification

## 1. Install and run

Open Terminal in this folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000** for the dashboard or **http://127.0.0.1:8000/docs** for interactive API docs.

Stop the server with `Ctrl+C`.

## 2. Demo Part 1 (regex and redaction)

Click these dashboard presets and then **Inspect payload**:
1. **Normal text** → `ALLOW`
2. **ID example** → `REDACT`, number replaced with `[REDACTED_NATIONAL_ID]`
3. **Card example** → `REDACT`, Luhn-valid synthetic card number replaced
4. **Ambiguous number** → `REVIEW` by default, number masked pending review

The card value `4111 1111 1111 1111` is a standard synthetic test number. Never enter real card or identity data.

## 3. Demo Part 2 (local AI)

Install Ollama from https://ollama.com, then in Terminal:

```bash
ollama pull llama3.2:3b
```

Keep Ollama running. The API uses `http://127.0.0.1:11434/api/generate` by default.

On the dashboard, select **Use local AI for ambiguous values** and test the **Ambiguous number** preset. Or run:

```bash
python client.py --ai
```

The model receives masked text, not the original candidate digits. It may still make mistakes. Strong, validated regex matches are always redacted regardless of AI output. If the AI service is unavailable or its response is invalid, the classifier returns a conservative fail-safe result.

Optional configuration:
```bash
export OLLAMA_URL=http://127.0.0.1:11434/api/generate
export OLLAMA_MODEL=llama3.2:3b
```

## 4. Demo upload blocking (403)

The `/proxy` endpoint takes the destination as a `url` query parameter. It blocks file-like POST/PUT/PATCH requests unless the destination hostname is in `DLP_UPLOAD_ALLOWLIST`.

Example (synthetic bytes, destination is not contacted because policy blocks it first):

```bash
curl -i -X POST \
  'http://127.0.0.1:8000/proxy?url=https%3A%2F%2Fuploads.example%2Fupload' \
  -H 'Content-Type: application/octet-stream' \
  --data-binary 'SYNTHETIC-DEMO-FILE'
```

Expected: `HTTP/1.1 403 Forbidden` and JSON explaining the allowlist policy.

To allow uploads to a specific destination, set its exact hostname explicitly before starting the app:
```bash
export DLP_UPLOAD_ALLOWLIST=approved.example.com
```
Only do this for a destination you control. The default allowlist is empty (deny by default).

The proxy also supports an optional forwarding allowlist:
```bash
export DLP_FORWARD_ALLOWLIST=api.example.com,approved.example.com
```
When set, only these hosts (plus upload-allowlisted hosts) can be forwarded. Keep local/private destinations blocked. `DLP_ALLOW_LOCAL_UPSTREAM=true` exists only for isolated local testing and should not be enabled on an untrusted network.

## 5. Run tests

```bash
pytest -q
```

## API summary

- `GET /` — demo dashboard
- `GET /health` — health check
- `POST /api/inspect` — inspect a JSON payload
- `ANY /proxy?url=https://destination.example/path` — policy-check and forward an HTTP request when allowed

Example inspect request:
```bash
curl -s http://127.0.0.1:8000/api/inspect \
  -H 'Content-Type: application/json' \
  -d '{"payload":"Customer identity number: 123456789012","use_ai":false}'
```

## Policy behavior

| Case | Behavior |
|---|---|
| Plain text | Allow |
| Luhn-valid card-like value | Redact |
| Explicitly labelled 12-digit identity number | Redact |
| Unlabelled 12-digit number | Review and mask; optional AI verification |
| Upload to non-allowlisted host | Block with HTTP 403 |
| AI unavailable/invalid output | Conservative fail-safe classification |

## Security notes and known limitations

- Use synthetic test values only. Do not collect or log real sensitive data.
- The demo dashboard uses local API calls. Do not expose the server to a public network.
- The proxy rejects local/private targets by default to reduce SSRF risk; DNS rebinding and sophisticated network policy issues require production-grade controls.
- The proxy forwards allowed requests with TLS verification enabled and redirects disabled. Review all destination and header policies before extending it.
- The demo's regexes are illustrative and are not a complete PCI-DSS or national-ID detector.
- Multipart uploads are detected and blocked by destination policy, but file contents are not deeply parsed or malware-scanned.
- Redaction changes text request bodies; this simple proxy does not rewrite JSON structure or update application-specific signatures.
- AI is probabilistic. It cannot replace deterministic mandatory rules, human review, or a tested policy engine.
- No real credentials, API keys, or user data are required.
