# AI Security Evaluator

A production-oriented, privacy-first, stateless AI/LLM security evaluation platform.

> This system is intended only for authorized security evaluation of AI systems.

## Overview

The platform evaluates authorized AI targets for:

- Prompt injection weakness
- Sensitive information disclosure
- Unauthorized action / excessive agency
- Adaptive attack resistance
- Evidence-validated findings
- Blast-radius assessment
- Security scoring and reporting

## Core Principles

1. **No persistent customer data**
   - No PostgreSQL
   - No MySQL
   - No SQLite
   - No MongoDB
   - No persistent Redis
   - No persistent vector database
   - No stored transcripts
   - No stored vulnerability history

2. **No persistent target credentials**
   - Target API keys live only in an ephemeral in-memory secret manager.
   - Keys are not placed in LangGraph state.
   - Keys are not written to logs, reports, prompts, or disk.

3. **Evidence-first evaluation**
   - LLM claims are not automatically trusted.
   - Deterministic scanners verify secrets, PII, permissions, and tool calls.
   - Metrics are calculated deterministically.

4. **Target output is untrusted**
   - Target responses are treated as adversarial input.
   - Instructions inside target output are not followed.

## Architecture

```text
Streamlit UI
  ↓
Ephemeral Session
  ↓
LangGraph Scan Orchestrator
  ↓
Attack Engine + Target Adapter + Evidence Engine
  ↓
Specialist Evaluators
  ↓
Deterministic Security Engine
  ↓
Temporary Vulnerability Memory
  ↓
Blast Radius Assessment
  ↓
Final Report
  ↓
Session Cleanup
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and configure evaluator model credentials.

Do **not** place target API keys in `.env`.

```bash
cp .env.example .env
```

Configure models in:

```text
configs/models.yaml
```

Configure scan profiles in:

```text
configs/security_profiles.yaml
```

## Run Locally

```bash
streamlit run frontend/streamlit_app.py
```

## Supported Target Providers

- OpenAI-compatible APIs
- Gemini-compatible APIs
- Ollama/local models
- Generic custom HTTP APIs
- Mock target for testing

## Example Scan

1. Open Streamlit UI.
2. Select provider.
3. Enter model/endpoint.
4. Enter target API key only if required.
5. Select scan profile.
6. Start evaluation.
7. Receive redacted final report.

## Testing

```bash
pytest tests -v
```

## Privacy Guarantees

- No persistent customer storage.
- No persistent credentials.
- No persistent transcripts.
- Explicit cleanup after scan.
- Report redaction before display.

## Threat Model

The evaluator itself is threatened by:

- Malicious target responses
- Prompt injection against evaluator reasoning
- Credential leakage
- Log leakage
- Malformed JSON
- Denial of service
- Excessive token usage
- Infinite attack loops

Mitigations:

- Target content is treated as untrusted.
- Evaluator prompts isolate target content.
- Resource limits stop scans.
- Structured output validation prevents malformed model output from corrupting state.
- Deterministic evidence checks reduce reliance on target or evaluator claims.

## Limitations

- LLM-based evaluation can miss novel vulnerabilities.
- Defense before/after comparison is limited unless paired metrics are supplied.
- External evaluator models may receive target responses during analysis.
  For sensitive environments, use local/private evaluator models.

## Responsible Use

Only evaluate systems you are authorized to test.
