# Journal-profile benchmark branch

This branch is designed to preserve the existing conference baseline while adding a
separate proof-aligned implementation for the journal revision.

## What is intentionally unchanged

- ML-KEM-768 / liboqs
- TCP client/server structure
- one registration followed by repeated login sessions
- warm-up and measured-run handling
- `client_round1`, `server_round2`, `net_rtt`, `client_finish`, `total_login`
- CSV column layout
- session-key equality check
- `CLOCK_MONOTONIC_RAW`

## Journal-only changes

1. **PPS**
   - long-term ML-KEM decapsulation key is no longer protected by `H1(pw)` directly.
   - a 16-byte per-user salt and Argon2id derive a password-dependent intermediate key.
   - the result is domain-separated and bound to `C,S,h_L,suite,ver`.
   - AES-256-GCM protects `dk_L` with associated data.

2. **Transcript binding**
   - outer-AE key uses `C,S,C1,C2,K_T`.
   - outer-AE associated data is `C,S,C1,C2`.
   - `sid = H("SID" || C || S || C1 || C2 || psi)`.
   - `SK = H("SK" || sid || K_T || K_L)`.

3. **Domain-preserving masking**
   - ML-KEM public-key coefficients are mapped with FF1 over radix `q=3329`.
   - ML-KEM ciphertext coefficients are decompressed to the `q`-ary domain,
     FF1-masked, and transmitted as 12-bit q-ary values.
   - this makes `C2 = 1536 B`, i.e. `+448 B` over the compressed 1088-byte
     ML-KEM-768 ciphertext.
   - the 32-byte `rho` field is masked separately with AES-CTR because its
     native format is the full byte-string domain.

## Message-size accounting

- `C1 = 1184 B`
- PPS record = `16 salt + 12 nonce + 32 h_L + 2400 encrypted dk_L
  + 16 GCM tag + 2 suite + 2 version = 2480 B`
- `C2 = 1536 B`
- `psi = 12 + (1088 + 2480) + 16 = 3596 B`
- total online payload = `1184 + 1536 + 3596 = 6316 B`

Baseline was 5816 B, so this concrete journal profile adds 500 B:
`448 B` from the q-ary ciphertext representation and `52 B` from PPS metadata
relative to the previous `tau` record.

## Argon2id profile

Default:
- memory = 64 MiB
- iterations = 3
- parallelism = 4
- salt = 16 B
- derived value = 32 B

This is the RFC 9106 second recommended Argon2id profile for memory-constrained
environments. Do a short pilot before a 30,000-session campaign because the
password KDF is deliberately expensive.

## Build

```bash
sudo apt update
sudo apt install -y libargon2-dev

chmod +x build_journal.sh
./build_journal.sh
```

## Smoke test

Server:
```bash
./apake_bench_journal server 8080 3 1
```

Client:
```bash
./apake_bench_journal client <SERVER_IP> 8080 3 1
```

Check:
- C1/C2/PSI sizes printed by the client
- no `Client_Finish failed`
- all session keys match

## Pilot before full experiment

Start with:
- 1 trial
- 10 warm-up
- 100 measured sessions

Then inspect `client_finish`; Argon2id is expected to dominate it.

## Final comparison

Run the *same network and CPU controls* for:
1. baseline `./apake_bench`
2. journal `./apake_bench_journal`

Do not compare results taken under different RTT, bandwidth, CPU governor,
core pinning, or VM configuration.
