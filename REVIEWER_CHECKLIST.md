# Reviewer-oriented implementation checklist

Before treating journal-profile measurements as paper results:

1. **Freeze the cryptographic profile**
   - ML-KEM-768 version / liboqs commit
   - Argon2id `m,t,p`
   - FF1 implementation/version
   - AES-256-GCM / OpenSSL version

2. **Do not claim that Argon2id determines all offline password-guess cost**
   while the temporary-layer verifier remains `hp = H0(pw)`.
   A leaked fast verifier can still provide a cheaper password test.
   In this implementation Argon2id is specifically the PPS storage-key derivation cost.

3. **Validate masking correctness**
   - `MaskPK_Dec(hp, MaskPK_Enc(hp, pk)) == pk`
   - `MaskCT_Dec(hp, MaskCT_Enc(hp, ct)) == ct`
   - all q-ary outputs remain in `[0,3328]`
   - ML-KEM decapsulation succeeds after round-trip

4. **Validate transcript binding**
   Flip one bit independently in `C1`, `C2`, `psi`, PPS metadata and confirm
   the relevant verification/decryption path rejects.

5. **Keep the baseline untouched**
   Run the original `src/apake_bench.c` and the journal binary separately.
   Do not overwrite the baseline binary/results.

6. **Freeze experimental controls**
   Same:
   - VM CPU/RAM
   - CPU affinity
   - CPU governor
   - RTT / bandwidth / packet-loss condition
   - compiler flags
   - OpenSSL/liboqs versions
   - warm-up / run count / trial count

7. **Pilot Argon2id first**
   The RFC 9106 64-MiB, t=3, p=4 profile is deliberately expensive.
   Do 100 measured sessions before scheduling 30,000.

8. **Report message sizes as application payload**
   Do not call 6316 B an Ethernet/TCP wire size.

9. **Report `net_rtt` accurately**
   It includes server processing and socket/OS/VM scheduling; it is not pure RTT.

10. **Paper wording**
   Baseline 8.886 ms and 1.503 ms values must remain labelled as conference
   baseline values unless the proof-compatible profile is remeasured.
