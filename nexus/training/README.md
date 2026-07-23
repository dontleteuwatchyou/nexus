# Nexus AI training

This directory prepares a specialised adapter; it does not redistribute a
base model. Training data must be public/licensed, synthetic, or produced in
an explicitly authorised lab.

## Hardware profile

The intended training machine is an RTX 4070 Ti. Start with a 3B–7B instruct
base model, 4-bit QLoRA, sequence length 2048 and batch size 1 with gradient
accumulation. The exact base model is configurable and must have a licence
compatible with Nexus distribution.

## Dataset format

Store private/raw data outside Git. The checked-in `examples.jsonl` only
documents the schema. Each line contains:

```json
{"messages":[{"role":"system","content":"..."},{"role":"user","content":"..."},{"role":"assistant","content":"..."}],"source":"synthetic-lab","license":"CC0-1.0","category":"osint"}
```

Never include secrets, breach dumps, personal data, credentials or output
collected from an unauthorised target. Prefer OWASP Juice Shop, WebGoat, DVWA,
Metasploitable and synthetic identities.

## Preparation

```bash
./install.sh --dev
.venv/bin/pip install -e '.[train]'
.venv/bin/python training/prepare_dataset.py \
  training/examples.jsonl training/ready.jsonl
```

The preparation command validates provenance, roles and content, removes exact
duplicates, and refuses records that look like secrets. `ready.jsonl` is
ignored by Git and can then be consumed by a TRL/PEFT QLoRA job.

Recommended curriculum:

1. target classification and Nexus module selection;
2. passive OSINT workflows and source evaluation;
3. result correlation, uncertainty and reporting;
4. authorised lab reconnaissance and vulnerability explanation;
5. defensive remediation and evidence handling;
6. tool-call traces produced by Nexus itself.

Evaluate on a held-out set. Measure target classification, correct tool choice,
unsupported claims, report quality and refusal of destructive/out-of-scope
actions rather than only training loss.
