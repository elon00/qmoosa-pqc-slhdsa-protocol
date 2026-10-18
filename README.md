# @qmoosa/pqc-slhdsa-protocol

[![CI Gate](https://github.com/elon00/qmoosa-pqc-slhdsa-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-slhdsa-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — NIST FIPS 205 Stateless Hash-Based Digital Signature Standard (SLH-DSA) Protocol Specification.

## Overview

`@qmoosa/pqc-slhdsa-protocol` provides canonical TypeScript types, parameter definitions, and byte-level invariant validations for NIST FIPS 205 (SLH-DSA, formerly SPHINCS+). SLH-DSA provides quantum-resistant digital signatures whose security relies strictly on the collision and preimage resistance of cryptographic hash functions (SHA-2 and SHAKE), requiring no lattice or number-theoretic assumptions.

## Parameter Sets (NIST FIPS 205)

| Parameter Set | Security Level | Hash Function | Mode | Public Key ($pk$) | Secret Key ($sk$) | Signature ($\sigma$) |
|---|---|---|---|---|---|---|
| `SLH-DSA-SHA2-128s` | NIST Level 1 | SHA-256 | Small Size | 32 B | 64 B | 7,856 B |
| `SLH-DSA-SHA2-128f` | NIST Level 1 | SHA-256 | Fast Speed | 32 B | 64 B | 17,088 B |
| `SLH-DSA-SHA2-192s` | NIST Level 3 | SHA-384 | Small Size | 48 B | 96 B | 16,224 B |
| `SLH-DSA-SHA2-256s` | NIST Level 5 | SHA-512 | Small Size | 64 B | 128 B | 29,792 B |
| `SLH-DSA-SHAKE-128s` | NIST Level 1 | SHAKE-256 | Small Size | 32 B | 64 B | 7,856 B |

## Key Properties

- **Stateless Operation:** No state tracking required between signing operations (unlike XMSS / LMS).
- **Conservative Hash Assumption:** Safe even if lattice problems (LWE, SIS) are compromised by new quantum algorithms.
- **Context Domain Separation:** Full support for FIPS 205 Section 5 context strings up to 255 bytes.

## Installation & Build

```bash
npm install
npm run build
npm test
```

## Reality Gate Status

- Production Deployment Status: **LOCKED (0 / 1,000 certified)**
- Local Reality-Gate Verification: **ACTIVE**
