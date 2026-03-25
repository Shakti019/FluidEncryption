# FluidEncryption

**FluidEncryption** is a Jupyter Notebook–based project that explains and demonstrates a complete **encryption → decryption** workflow in a clear, reproducible way.  
The notebook is written to help you understand *why* each cryptographic step exists (keying, nonce/IV, authentication, verification), not just to run code.

> Status: Draft / Learning + Portfolio Project  
> Last updated: **2025-12-11**

---

## Table of Contents
- [Algorithm Analysis (How the Crypto Works)](#algorithm-analysis-how-the-crypto-works)
  - [1) Problem Statement](#1-problem-statement)
  - [2) Threat Model (What We Protect Against)](#2-threat-model-what-we-protect-against)
  - [3) Design Choice: Symmetric Encryption](#3-design-choice-symmetric-encryption)
  - [4) Key Material: Key Generation vs Key Derivation](#4-key-material-key-generation-vs-key-derivation)
  - [5) Nonce / IV (Why It Matters)](#5-nonce--iv-why-it-matters)
  - [6) Encryption + Authentication (AEAD)](#6-encryption--authentication-aead)
  - [7) What Gets Stored/Transmitted](#7-what-gets-storedtransmitted)
  - [8) Decryption + Verification](#8-decryption--verification)
  - [9) Common Mistakes This Project Avoids](#9-common-mistakes-this-project-avoids)
- [Project Goals](#project-goals)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Results / Output](#results--output)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [License](#license)

---

# Algorithm Analysis (How the Crypto Works)

## 1) Problem Statement
We want to transform an input **plaintext** (message/data) into **ciphertext** so that:
- An attacker who sees the ciphertext cannot recover the plaintext (**confidentiality**)
- Ideally, modifications to ciphertext are detected (**integrity + authenticity**)

This project demonstrates the full lifecycle:
**plaintext → encryption → ciphertext (+ metadata) → decryption → plaintext**

---

## 2) Threat Model (What We Protect Against)
This notebook is designed for typical real-world scenarios where:
- Attackers can read stored or transmitted ciphertext
- Attackers may try to tamper with ciphertext
- The secret key must remain private

It is **not** designed to protect against:
- Key theft from an infected machine
- Weak passwords used as keys (unless a strong KDF is used)
- Side-channel attacks (timing/power analysis)

---

## 3) Design Choice: Symmetric Encryption
FluidEncryption uses **symmetric cryptography**: the same secret key is used for both encryption and decryption.

Why symmetric?
- Fast for large data
- Simple mental model for learning
- Matches most practical “encrypt a file/message” use cases

---

## 4) Key Material: Key Generation vs Key Derivation
There are two correct ways to get a symmetric key:

### A) Random key generation (recommended for pure demos)
- Generate a cryptographically secure random key of required length (e.g., 256-bit)

### B) Password-based key derivation (recommended when humans provide a password)
- Use a KDF like **PBKDF2 / scrypt / Argon2**
- Include a random **salt**
- Use a high work factor (iterations/memory)

**Why not use the password directly?**  
Human passwords have low entropy and are vulnerable to brute-force attacks without a KDF.

> In the notebook, choose one approach and document it clearly:
- **Key source:** `[Random key | Password + KDF]`
- **KDF params:** `[algorithm, iterations, salt size]`

---

## 5) Nonce / IV (Why It Matters)
Most modern encryption modes require a unique per-encryption value:
- **Nonce** (number used once) or **IV** (initialization vector)

Why it matters:
- Reusing a nonce/IV with the same key can leak information and can break security
- Nonces/IVs are usually safe to store/transmit openly with ciphertext

Typical rule:
- **Never reuse a nonce/IV with the same key.**

---

## 6) Encryption + Authentication (AEAD)
Modern best practice is **AEAD** (Authenticated Encryption with Associated Data), e.g.:
- **AES-GCM** or **ChaCha20-Poly1305**

AEAD gives you:
- Confidentiality (encryption)
- Integrity/authenticity (authentication tag)
- Automatic detection of tampering (wrong tag ⇒ decryption fails)

If you are using AES-CBC (or similar), you must add authentication separately (e.g., HMAC).
AEAD avoids many classic mistakes by design.

> **Algorithm used in this repo:** `[AES-GCM | ChaCha20-Poly1305 | AES-CBC+HMAC | Custom]`

---

## 7) What Gets Stored/Transmitted
A correct encryption output is not only ciphertext. You also need metadata required for decryption.

Typical bundle:
- `salt` (if using password → key derivation)
- `nonce/iv`
- `ciphertext`
- `tag` (for AEAD modes)
- optional: `kdf params` / `version`

This notebook demonstrates how these pieces fit together and how to reconstruct them during decryption.

---

## 8) Decryption + Verification
Decryption reverses the process:
1. Load metadata (salt/nonce/tag)
2. Re-derive key (if using password + KDF) OR load saved key (if random-key mode)
3. Decrypt ciphertext
4. Verify integrity:
   - AEAD modes verify automatically via tag
   - If using HMAC, verify HMAC before decrypting

Output should match original plaintext:
- `decrypted_plaintext == original_plaintext` → ✅ PASS

---

## 9) Common Mistakes This Project Avoids
- ❌ Using insecure modes like ECB
- ❌ Reusing nonce/IV for the same key
- ❌ Storing secrets directly in notebook output cells
- ❌ Skipping integrity/authentication (AEAD strongly preferred)

---

## Project Goals
- Provide a clean and understandable implementation of an encryption pipeline
- Make cryptography concepts easier to learn through runnable experiments
- Offer a notebook workflow suitable for demos, assignments, and portfolio presentation

---

## Key Features
- ✅ End-to-end workflow: **key generation/derivation → encryption → decryption → verification**
- ✅ Notebook-first: explanation + code + outputs
- ✅ Parameterized configuration (KDF params, key size, mode, etc.)
- ✅ Validation checks to confirm decrypted output matches input
- ✅ Optional experiments (timing/benchmarking, multiple inputs)

---

## Tech Stack
- **Language:** Python (Jupyter Notebook)
- **Environment:** Jupyter Notebook / JupyterLab
- **Crypto Library:** `[cryptography | pycryptodome]`
- Optional: `numpy`, `pandas`, `matplotlib` (if used)

---

## Project Structure
> Update this to match your repo.

```text
FluidEncryption/
├── notebooks/
│   └── FluidEncryption.ipynb
├── outputs/
│   ├── encrypted.bin
│   └── decrypted.txt
├── requirements.txt
└── README.md
```

---

## Getting Started

### 1) Clone the repository
```bash
git clone https://github.com/Shakti019/FluidEncryption.git
cd FluidEncryption
```

### 2) Create and activate a virtual environment (recommended)
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
```

### 3) Install dependencies
```bash
pip install -r requirements.txt
```

If you don’t have `requirements.txt` yet:
```bash
pip install jupyter cryptography
```

### 4) Run Jupyter
```bash
jupyter notebook
```

Open the notebook:
- `notebooks/FluidEncryption.ipynb` (or your actual notebook name)

---

## Usage
In the notebook:
1. Choose input type: **text / bytes / file** (depending on your implementation)
2. Configure crypto parameters (key derivation, mode, nonce behavior)
3. Run cells to:
   - generate/derive key
   - encrypt
   - decrypt
   - verify results

---

## Results / Output
- Produces ciphertext + metadata (nonce/iv, optional salt/tag)
- Decryption restores original plaintext
- Verification prints a clear **PASS/FAIL** result

---

## Security Notes
This repository is primarily for **learning and demonstration**.
If you plan to extend it for real use:
- Prefer AEAD modes (AES-GCM / ChaCha20-Poly1305)
- Never reuse nonce/IV for a given key
- Don’t hardcode keys/passwords in notebooks
- Consider adding tests and a CLI wrapper

---

## Roadmap
- [ ] Finalize and document the exact algorithm choice (mode, key size, KDF)
- [ ] Add file encryption support (input/output files)
- [ ] Add unit tests for correctness + edge cases
- [ ] Add benchmarking (time per KB/MB)
- [ ] Add a CLI (`python -m fluidencryption ...`)

---

## License
Not specified yet. Consider adding **MIT** or **Apache-2.0** if you plan to share it publicly.
