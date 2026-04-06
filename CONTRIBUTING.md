# Contributing to AISS

Thank you for your interest in contributing to the Agent Identity and Signature Standard.

---

## What can be contributed

**Spec improvements**
Clarifications, corrections, or additions to the RFC. Open an issue first to discuss before writing.

**Test vectors**
New normative test vectors in `test_vectors/`. These are the most valuable contribution — they define what conformance means for every implementation.

**Bug reports**
If you find a discrepancy between the spec and the reference implementation, open an issue with a minimal reproduction.

**Implementations**
If you have implemented AISS in another language, open a PR to add it to the Implementations section of the README.
Requirements: pass all normative test vectors in `test_vectors/`, provide a link to your repository.

---

## What is out of scope here

This repository is the AISS standard and its reference Python package.

- Framework bridges (LangChain, CrewAI, etc.) → [PiQrypt](https://github.com/piqrypt/piqrypt)
- Vigil Pro, TrustGate, certified exports → [PiQrypt](https://github.com/piqrypt/piqrypt)
- Encrypted memory, .pqz archives → [PiQrypt](https://github.com/piqrypt/piqrypt)

---

## Process

1. Open an issue before significant changes
2. Fork the repository
3. Create a branch: `fix/description` or `feat/description`
4. Make your changes
5. Run the test suite: `pytest tests/`
6. Open a pull request against `main`

All working groups operate openly. No membership required to contribute.

---

## Contact

- Spec questions / bugs → [GitHub Issues](https://github.com/piqrypt/aiss-standard/issues)
- Security vulnerabilities → contact@piqrypt.com (do not open a public issue)
- Conformance / partnerships → contact@piqrypt.com

---

## Commit message format

```
type: brief description

Longer explanation if needed.
```

Types: `spec`, `fix`, `test`, `docs`, `feat`, `chore`

Examples:
```
spec: clarify fork resolution rule in §10.2
fix: correct event hash in test vector events.json
test: add rotation vector for key continuity
docs: update API.md with AgentIdentity examples
```
