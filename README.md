# CipherBreaker

[![C#](https://img.shields.io/badge/Language-C%23-blue?logo=c-sharp&logoColor=white)](https://docs.microsoft.com/en-us/dotnet/csharp/)
[![.NET](https://img.shields.io/badge/Framework-.NET-blueviolet?logo=.net)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Cryptanalysis: breaking classical ciphers with **no key given**.

---

## How this differs from CryptoPortfolio

[CryptoPortfolio](https://github.com/neogentrics/CryptoPortfolio) implements 38 classical ciphers
and demonstrates each one with a known key: encrypt, decrypt, verify the round-trip. Its own
Universal Decrypt tool goes one step further — try a *guessed* codeword against every cipher — but
that is still identification, not cryptanalysis: a human supplies a candidate key.

CipherBreaker takes ciphertext **only**. No key, no guess — the attack has to find one. That is a
genuinely different problem: frequency analysis, statistical scoring, and exhaustive or heuristic
search over a keyspace, rather than a menu-driven encrypt/decrypt demo. It references
`CryptoPortfolio.Core` directly as a project dependency, so cipher implementations are never
duplicated — CipherBreaker's job is exclusively the *attacking* half.

---

## What's here

* **Frequency Analysis** — letter-frequency counting, chi-squared scoring against standard English
  frequencies (the scoring function every solver here uses to judge a candidate decryption), and
  the Index of Coincidence (Friedman's formula, useful for telling monoalphabetic ciphers apart
  from polyalphabetic ones before attempting to break either).
* **Caesar Solver** — brute-forces all 26 shifts and picks the one that scores most English-like.
  Small keyspace, but the scoring problem it solves — "which of many gibberish outputs is actually
  English?" — is the same problem every more advanced attack here has to solve too.
* **Simple Substitution Solver** — 26! possible keys rules out brute force, so this hill-climbs: a
  random starting key is repeatedly refined by swapping letter pairs and keeping any swap that
  scores better against a bigram model trained on real English (computed from 563,955 letters of
  Jane Austen's *Pride and Prejudice*, not a remembered frequency table), with many random restarts
  to escape wrong local optima. Verified against genuinely held-out text — a different author,
  Arthur Conan Doyle — with zero key given: exact recovery, 1,663 characters, in under 2 seconds.
* **Vigenère Solver** — three centuries of "le chiffre indéchiffrable" fell to two techniques,
  both reused here: **Kasiski examination** (1863) finds repeated ciphertext sequences and votes on
  key lengths from the distances between them; **Index of Coincidence** (Friedman, 1922) confirms
  the estimate statistically, since the correct key length is the one whose columns each look like
  plain English. Once the length is known, every column of the ciphertext is exactly a Caesar
  cipher — so **the existing Caesar Solver is reused unchanged**, one call per key position, to
  recover the whole key. Verified on the same held-out Conan Doyle text with five different keys
  (3 to 13 letters): exact key and exact plaintext recovered every time, with zero key given.
* **Hill Known-Plaintext Attack** — a genuinely different attack model from everything above: not
  ciphertext-only, but a **crib** (plaintext you know or suspect appears in the message, position
  unknown). Given two independent plaintext digraphs and their matching ciphertext, the 2x2 key
  matrix K isn't merely likely, it's *uniquely determined*: K = C x P^-1 (mod 26). This is exact
  linear algebra, not a statistical guess — no hill-climbing, nothing probabilistic. What's
  genuinely searched is the alignment, since a crib can only line up with Hill's fixed two-letter
  blocks at an even offset. Verified against real ciphertext with an unknown key: exact key and
  plaintext recovered instantly, crib position found automatically. One real bug caught while
  verifying it: pairing a crib's *first* digraph with each later one fails outright whenever that
  first digraph's own letters are both even-valued (their column vector forces every determinant
  even) — fixed by trying every pair of digraphs in the crib, not just those anchored to the first.

---

## Roadmap

* [x] Frequency analysis infrastructure (chi-squared, Index of Coincidence)
* [x] Caesar cipher solver (exhaustive search)
* [x] Simple substitution solver (hill-climbing over a corpus-trained bigram model)
* [x] Vigenère solver (Kasiski + Index of Coincidence for key length, Caesar solver per position)
* [x] Known-plaintext attack against the Hill cipher (exact linear algebra, crib alignment unknown)
* [ ] Affine cipher solver (small keyspace, same exhaustive-search approach as Caesar)
* [ ] Bombe-style attack against the Enigma simulator already implemented in CryptoPortfolio

---

## Technology Stack

* **Language:** C#
* **Framework:** .NET 9 (cross-platform)
* **Testing:** xUnit
* **Depends on:** [CryptoPortfolio](https://github.com/neogentrics/CryptoPortfolio) (cipher
  implementations, referenced as a sibling project — clone both repos as siblings for the reference
  to resolve)

---

## Installation & Usage

```bash
git clone https://github.com/neogentrics/CryptoPortfolio.git
git clone https://github.com/neogentrics/CipherBreaker.git
cd CipherBreaker
dotnet run --project CipherBreaker.Console
```

### Running the tests

```bash
dotnet test
```

Every solver is tested the way an attacker actually uses it: ciphertext goes in, no key is given,
and the test asserts the correct key and plaintext come out anyway.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
