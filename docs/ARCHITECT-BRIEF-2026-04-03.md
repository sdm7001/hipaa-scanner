# HIPAA Scanner — Architect Brief
**Date**: 2026-04-03
**Status**: Awaiting research completion before architect engagement

## Context
Two research documents have been prepared for the architect:
1. `HIPAA-RESEARCH-2026-04-03.md` — Full regulatory requirements (HIPAA Security Rule, HITECH, OCR, NIST)
2. `CODEBASE-ANALYSIS-2026-04-03.md` — Complete existing codebase gap analysis

## Product Goal (from client)
Build a production-ready, multi-tenant HIPAA network compliance scanner that:
- Discovers and scans EVERY NODE on a client network
- Documents compliance against strictest HIPAA rules
- Generates comprehensive reports with remediation recommendations
- Supports installable collector agent for client networks
- Has a multi-tenant portal (MSP model: one portal, many clients)
- Is commercially deployable

## Architect Deliverables Required
1. Complete technical architecture document
2. Component breakdown with implementation specs
3. Database schema additions/changes
4. API contract (all new endpoints)
5. Collector agent design (protocol, security, packaging)
6. New HIPAA check specifications (50+ total target)
7. Implementation phases with priorities
8. Technology decisions with rationale

## Constraints
- Python backend (FastAPI) — keep existing stack
- React/TypeScript frontend — keep existing stack
- Windows collector primary target, Linux secondary
- Must work agentless (WinRM) AND with installed agent
- All data encrypted in transit and at rest
