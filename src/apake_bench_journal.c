/*
 * apake_bench_journal.c
 * ------------------------------------------------------------------
 * Journal-profile implementation for the Dual-KEM 2-pass PQC aPAKE.
 *
 * This file intentionally keeps the baseline benchmark structure:
 *   - ML-KEM-768 via liboqs
 *   - TCP client/server
 *   - same timing intervals and CSV columns
 *   - same warm-up / measured-run handling
 *
 * Journal-only changes:
 *   1) password-protected storage (PPS)
 *      Argon2id -> context-bound storage key -> AES-256-GCM
 *   2) transcript-bound outer AE
 *      K_A = H("AE" || C || S || C1 || C2 || K_T)
 *      AAD = C || S || C1 || C2
 *   3) proof-compatible domain-preserving masking
 *      - temporary ML-KEM public-key coefficients: FF1 over radix q=3329
 *      - temporary ciphertext: decompress to q-ary coefficients, FF1, then
 *        send as 12-bit q-ary representation (1536 B; +448 B vs 1088 B)
 *      - the 32-byte rho part of the ML-KEM public key is masked with
 *        AES-CTR because its native domain is the full 256-bit string space.
 *
 * IMPORTANT:
 *   - The original src/apake_bench.c remains the conference baseline.
 *   - This file is a separate journal-profile benchmark.
 *   - Argon2id defaults follow RFC 9106's second recommended profile:
 *       m=64 MiB, t=3, p=4, salt=16 B, output=32 B.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -Wno-deprecated-declarations \
 *       -I/usr/local/include -L/usr/local/lib \
 *       src/apake_bench_journal.c -o apake_bench_journal \
 *       -loqs -lcrypto -largon2 -lm
 * ------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bn.h>

#include <argon2.h>
#include <oqs/oqs.h>

#define KEM_ALG              "ML-KEM-768"

#define KEM_PK_BYTES         1184
#define KEM_SK_BYTES         2400
#define KEM_CT_BYTES         1088
#define KEM_SS_BYTES         32

#define MLKEM_Q              3329
#define MLKEM_K              3
#define MLKEM_N              256
#define PK_COEFFS             (MLKEM_K * MLKEM_N)   /* 768 */
#define CT_U_COEFFS           (MLKEM_K * MLKEM_N)   /* 768 */
#define CT_V_COEFFS           MLKEM_N                /* 256 */
#define CT_Q_COEFFS           (CT_U_COEFFS + CT_V_COEFFS) /* 1024 */
#define PK_COEFF_BYTES        1152
#define PK_RHO_BYTES          32
#define CT_U_BYTES            960
#define CT_V_BYTES            128

#define AE_KEY_BYTES         32
#define AE_NONCE_BYTES       12
#define AE_TAG_BYTES         16
#define LAMBDA_BYTES         32

#define PPS_SALT_BYTES       16
#define PPS_BIND_BYTES       32
#define PPS_SUITE_BYTES      2
#define PPS_VER_BYTES        2
#define PPS_CT_BYTES         KEM_SK_BYTES

/* RFC 9106 second recommended profile for memory-constrained environments. */
#define ARGON2_T_COST         3
#define ARGON2_M_COST_KIB     65536
#define ARGON2_PARALLELISM    4

/* q-ary 12-bit representation: 1024 * 12 / 8 = 1536 bytes */
#define C1_BYTES             KEM_PK_BYTES
#define C2_BYTES             ((CT_Q_COEFFS * 12) / 8)

#define PPS_RECORD_BYTES     (PPS_SALT_BYTES + AE_NONCE_BYTES + PPS_BIND_BYTES + \
                              PPS_CT_BYTES + AE_TAG_BYTES + PPS_SUITE_BYTES + PPS_VER_BYTES)

#define PSI_PLAIN_BYTES      (KEM_CT_BYTES + PPS_RECORD_BYTES)
#define PSI_BYTES            (AE_NONCE_BYTES + PSI_PLAIN_BYTES + AE_TAG_BYTES)
#define TOTAL_LOGIN_BYTES    (C1_BYTES + C2_BYTES + PSI_BYTES)

typedef struct {
    int measured_runs;
    int warmup_runs;
    int c1_bytes;
    int c2_bytes;
    int psi_bytes;
    int total_login_bytes;
} BenchParams;

typedef struct {
    uint8_t salt[PPS_SALT_BYTES];
    uint8_t nonce[AE_NONCE_BYTES];
    uint8_t hL[PPS_BIND_BYTES];
    uint8_t enc_dk[PPS_CT_BYTES];
    uint8_t tag[AE_TAG_BYTES];
    uint8_t suite[PPS_SUITE_BYTES];
    uint8_t ver[PPS_VER_BYTES];
} PPSRecord;

typedef struct {
    uint8_t hp[LAMBDA_BYTES];     /* temporary-layer verifier */
    uint8_t ekL[KEM_PK_BYTES];    /* long-term ML-KEM encapsulation key */
    PPSRecord pps;                /* protected long-term decapsulation key */
} ServerRecord;

typedef struct {
    uint8_t eph_pk[KEM_PK_BYTES];
    uint8_t eph_sk[KEM_SK_BYTES];
    uint8_t hp[LAMBDA_BYTES];
    uint8_t KT[LAMBDA_BYTES];
    uint8_t C1[C1_BYTES];
} ClientState;

static OQS_KEM *g_kem = NULL;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int readn(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        p += r;
        left -= (size_t)r;
    }
    return 0;
}

static int writen(int fd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += w;
        left -= (size_t)w;
    }
    return 0;
}

static void set_tcp_nodelay(int fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int random_bytes(uint8_t *out, size_t len)
{
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}

/* ------------------------------------------------------------------
 * Hash / KDF helpers
 * ------------------------------------------------------------------ */

static void hash_begin(SHA256_CTX *c, const char *label)
{
    SHA256_Init(c);
    SHA256_Update(c, label, strlen(label));
}

static void H0_hp(const char *pw, uint8_t hp[LAMBDA_BYTES])
{
    SHA256_CTX c;
    hash_begin(&c, "H0-hp");
    SHA256_Update(&c, pw, strlen(pw));
    SHA256_Final(hp, &c);
}

static void H_bind(const uint8_t ekL[KEM_PK_BYTES],
                   uint8_t hL[PPS_BIND_BYTES])
{
    SHA256_CTX c;
    hash_begin(&c, "PPS-BIND");
    SHA256_Update(&c, ekL, KEM_PK_BYTES);
    SHA256_Final(hL, &c);
}

static void G_KT(const char *C, const char *S,
                 const uint8_t eph_pk[KEM_PK_BYTES],
                 const uint8_t eph_ct[KEM_CT_BYTES],
                 const uint8_t eph_ss[KEM_SS_BYTES],
                 uint8_t KT[LAMBDA_BYTES])
{
    SHA256_CTX c;
    hash_begin(&c, "G-KT");
    SHA256_Update(&c, C, strlen(C));
    SHA256_Update(&c, S, strlen(S));
    SHA256_Update(&c, eph_pk, KEM_PK_BYTES);
    SHA256_Update(&c, eph_ct, KEM_CT_BYTES);
    SHA256_Update(&c, eph_ss, KEM_SS_BYTES);
    SHA256_Final(KT, &c);
}

static void H_A(const char *C, const char *S,
                const uint8_t C1[C1_BYTES],
                const uint8_t C2[C2_BYTES],
                const uint8_t KT[LAMBDA_BYTES],
                uint8_t KA[AE_KEY_BYTES])
{
    SHA256_CTX c;
    hash_begin(&c, "AE");
    SHA256_Update(&c, C, strlen(C));
    SHA256_Update(&c, S, strlen(S));
    SHA256_Update(&c, C1, C1_BYTES);
    SHA256_Update(&c, C2, C2_BYTES);
    SHA256_Update(&c, KT, LAMBDA_BYTES);
    SHA256_Final(KA, &c);
}

static void H_sid(const char *C, const char *S,
                  const uint8_t C1[C1_BYTES],
                  const uint8_t C2[C2_BYTES],
                  const uint8_t psi[PSI_BYTES],
                  uint8_t sid[LAMBDA_BYTES])
{
    SHA256_CTX c;
    hash_begin(&c, "SID");
    SHA256_Update(&c, C, strlen(C));
    SHA256_Update(&c, S, strlen(S));
    SHA256_Update(&c, C1, C1_BYTES);
    SHA256_Update(&c, C2, C2_BYTES);
    SHA256_Update(&c, psi, PSI_BYTES);
    SHA256_Final(sid, &c);
}

static void H_sk(const uint8_t sid[LAMBDA_BYTES],
                 const uint8_t KT[LAMBDA_BYTES],
                 const uint8_t KL[KEM_SS_BYTES],
                 uint8_t ssk[LAMBDA_BYTES])
{
    SHA256_CTX c;
    hash_begin(&c, "SK");
    SHA256_Update(&c, sid, LAMBDA_BYTES);
    SHA256_Update(&c, KT, LAMBDA_BYTES);
    SHA256_Update(&c, KL, KEM_SS_BYTES);
    SHA256_Final(ssk, &c);
}

static size_t build_ctx_aad(const char *C, const char *S,
                            const uint8_t C1[C1_BYTES],
                            const uint8_t C2[C2_BYTES],
                            uint8_t *out, size_t cap)
{
    size_t lc = strlen(C), ls = strlen(S);
    size_t need = lc + ls + C1_BYTES + C2_BYTES;
    if (cap < need) return 0;
    size_t off = 0;
    memcpy(out + off, C, lc); off += lc;
    memcpy(out + off, S, ls); off += ls;
    memcpy(out + off, C1, C1_BYTES); off += C1_BYTES;
    memcpy(out + off, C2, C2_BYTES); off += C2_BYTES;
    return off;
}

static size_t build_pps_aad(const char *C, const char *S,
                            const PPSRecord *r,
                            uint8_t *out, size_t cap)
{
    size_t lc = strlen(C), ls = strlen(S);
    size_t need = lc + ls + PPS_BIND_BYTES + PPS_SUITE_BYTES + PPS_VER_BYTES;
    if (cap < need) return 0;
    size_t off = 0;
    memcpy(out + off, C, lc); off += lc;
    memcpy(out + off, S, ls); off += ls;
    memcpy(out + off, r->hL, PPS_BIND_BYTES); off += PPS_BIND_BYTES;
    memcpy(out + off, r->suite, PPS_SUITE_BYTES); off += PPS_SUITE_BYTES;
    memcpy(out + off, r->ver, PPS_VER_BYTES); off += PPS_VER_BYTES;
    return off;
}

/*
 * Argon2id produces an expensive password-dependent intermediate key.
 * SHA-256 then binds that result to the PPS role and public context.
 */
static int derive_Kst(const char *C, const char *S, const char *pw,
                      const PPSRecord *r,
                      uint8_t Kst[AE_KEY_BYTES])
{
    uint8_t raw[AE_KEY_BYTES];
    int rc = argon2id_hash_raw(ARGON2_T_COST,
                               ARGON2_M_COST_KIB,
                               ARGON2_PARALLELISM,
                               pw, strlen(pw),
                               r->salt, PPS_SALT_BYTES,
                               raw, sizeof(raw));
    if (rc != ARGON2_OK) {
        fprintf(stderr, "Argon2id failed: %s\n", argon2_error_message(rc));
        return -1;
    }

    SHA256_CTX c;
    hash_begin(&c, "PPS");
    SHA256_Update(&c, raw, sizeof(raw));
    SHA256_Update(&c, C, strlen(C));
    SHA256_Update(&c, S, strlen(S));
    SHA256_Update(&c, r->hL, PPS_BIND_BYTES);
    SHA256_Update(&c, r->suite, PPS_SUITE_BYTES);
    SHA256_Update(&c, r->ver, PPS_VER_BYTES);
    SHA256_Final(Kst, &c);
    OPENSSL_cleanse(raw, sizeof(raw));
    return 0;
}

/* ------------------------------------------------------------------
 * AES-256-GCM with associated data.
 * Outer-AE wire format = nonce || ciphertext || tag.
 * PPS stores nonce/ciphertext/tag as separate record fields.
 * ------------------------------------------------------------------ */

static int gcm_encrypt_explicit(const uint8_t key[AE_KEY_BYTES],
                                const uint8_t nonce[AE_NONCE_BYTES],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t *ct,
                                uint8_t tag[AE_TAG_BYTES])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AE_NONCE_BYTES, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ct + total, &len) != 1) goto done;
    total += len;
    if ((size_t)total != pt_len) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AE_TAG_BYTES, tag) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int gcm_decrypt_explicit(const uint8_t key[AE_KEY_BYTES],
                                const uint8_t nonce[AE_NONCE_BYTES],
                                const uint8_t *aad, size_t aad_len,
                                const uint8_t *ct, size_t ct_len,
                                const uint8_t tag[AE_TAG_BYTES],
                                uint8_t *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AE_NONCE_BYTES, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto done;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AE_TAG_BYTES, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + total, &len) != 1) goto done;
    total += len;
    if ((size_t)total != ct_len) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int AE_Enc_AAD(const uint8_t key[AE_KEY_BYTES],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *pt, size_t pt_len,
                      uint8_t *out, size_t out_len)
{
    if (out_len != AE_NONCE_BYTES + pt_len + AE_TAG_BYTES) return -1;
    uint8_t *nonce = out;
    uint8_t *ct = out + AE_NONCE_BYTES;
    uint8_t *tag = out + AE_NONCE_BYTES + pt_len;
    if (random_bytes(nonce, AE_NONCE_BYTES) != 0) return -1;
    return gcm_encrypt_explicit(key, nonce, aad, aad_len, pt, pt_len, ct, tag);
}

static int AE_Dec_AAD(const uint8_t key[AE_KEY_BYTES],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t in_len,
                      uint8_t *pt, size_t pt_len)
{
    if (in_len != AE_NONCE_BYTES + pt_len + AE_TAG_BYTES) return -1;
    const uint8_t *nonce = in;
    const uint8_t *ct = in + AE_NONCE_BYTES;
    const uint8_t *tag = in + AE_NONCE_BYTES + pt_len;
    return gcm_decrypt_explicit(key, nonce, aad, aad_len, ct, pt_len, tag, pt);
}

/* ------------------------------------------------------------------
 * FF1 (NIST SP 800-38G) over radix q=3329.
 * The implementation uses AES-256 as CIPH and BIGNUM only for exact
 * integer arithmetic; no floating-point arithmetic is used.
 * ------------------------------------------------------------------ */

static int aes256_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16])
{
    AES_KEY aes;
    if (AES_set_encrypt_key(key, 256, &aes) != 0) return -1;
    AES_encrypt(in, out, &aes);
    return 0;
}

static void xor16(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    for (int i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
}

static int ff1_prf(const uint8_t key[32], const uint8_t *data, size_t len,
                   uint8_t out[16])
{
    if (len % 16 != 0) return -1;
    uint8_t y[16] = {0}, x[16];
    for (size_t off = 0; off < len; off += 16) {
        xor16(x, y, data + off);
        if (aes256_block(key, x, y) != 0) return -1;
    }
    memcpy(out, y, 16);
    return 0;
}

static BIGNUM *digits_to_bn(const uint16_t *x, size_t n, uint32_t radix)
{
    BIGNUM *v = BN_new();
    if (!v) return NULL;
    BN_zero(v);
    for (size_t i = 0; i < n; i++) {
        if (!BN_mul_word(v, radix) || !BN_add_word(v, x[i])) {
            BN_free(v);
            return NULL;
        }
    }
    return v;
}

static int bn_to_digits(const BIGNUM *v, uint16_t *out, size_t n, uint32_t radix)
{
    BIGNUM *tmp = BN_dup(v);
    if (!tmp) return -1;
    for (size_t i = n; i-- > 0;) {
        BN_ULONG rem = BN_div_word(tmp, radix);
        if (rem == (BN_ULONG)-1) { BN_free(tmp); return -1; }
        out[i] = (uint16_t)rem;
    }
    int ok = BN_is_zero(tmp);
    BN_free(tmp);
    return ok ? 0 : -1;
}

static size_t ceil_div(size_t a, size_t b)
{
    return (a + b - 1) / b;
}

static int ff1_q_crypt(const uint8_t key[32],
                       const uint8_t *tweak, size_t t,
                       const uint16_t *in, uint16_t *out, size_t n,
                       int decrypt)
{
    const uint32_t radix = MLKEM_Q;
    if (n < 2) return -1;
    for (size_t i = 0; i < n; i++) if (in[i] >= radix) return -1;

    size_t u = n / 2, v = n - u;

    /* Exact b = ceil(ceil(v*log2(radix))/8) without floating point:
       choose the smallest b such that 256^b >= radix^v. */
    BIGNUM *rv = BN_new(), *pow256 = BN_new();
    BN_CTX *bnctx = BN_CTX_new();
    if (!rv || !pow256 || !bnctx) { BN_free(rv); BN_free(pow256); BN_CTX_free(bnctx); return -1; }
    BN_set_word(rv, radix);
    BIGNUM *rvpow = BN_new();
    if (!rvpow || !BN_exp(rvpow, rv, BN_value_one(), bnctx)) { /* placeholder reset below */ }
    BN_free(rvpow);

    BIGNUM *radix_v = BN_new();
    BIGNUM *expv = BN_new();
    if (!radix_v || !expv) { BN_free(rv); BN_free(pow256); BN_free(radix_v); BN_free(expv); BN_CTX_free(bnctx); return -1; }
    BN_set_word(expv, (BN_ULONG)v);
    if (!BN_exp(radix_v, rv, expv, bnctx)) {
        BN_free(rv); BN_free(pow256); BN_free(radix_v); BN_free(expv); BN_CTX_free(bnctx); return -1;
    }
    BN_one(pow256);
    size_t b = 0;
    while (BN_cmp(pow256, radix_v) < 0) {
        if (!BN_lshift(pow256, pow256, 8)) {
            BN_free(rv); BN_free(pow256); BN_free(radix_v); BN_free(expv); BN_CTX_free(bnctx); return -1;
        }
        b++;
    }
    BN_free(rv); BN_free(pow256); BN_free(radix_v); BN_free(expv);

    size_t d = 4 * ceil_div(b, 4) + 4;
    uint8_t P[16] = {0};
    P[0] = 1; P[1] = 2; P[2] = 1;
    P[3] = (uint8_t)(radix >> 16);
    P[4] = (uint8_t)(radix >> 8);
    P[5] = (uint8_t)radix;
    P[6] = 10;
    P[7] = (uint8_t)(u & 0xff);
    P[8] = (uint8_t)(n >> 24);
    P[9] = (uint8_t)(n >> 16);
    P[10] = (uint8_t)(n >> 8);
    P[11] = (uint8_t)n;
    P[12] = (uint8_t)(t >> 24);
    P[13] = (uint8_t)(t >> 16);
    P[14] = (uint8_t)(t >> 8);
    P[15] = (uint8_t)t;

    uint16_t *A = calloc(v > u ? v : u, sizeof(uint16_t));
    uint16_t *B = calloc(v > u ? v : u, sizeof(uint16_t));
    uint16_t *C = calloc(v > u ? v : u, sizeof(uint16_t));
    if (!A || !B || !C) { free(A); free(B); free(C); BN_CTX_free(bnctx); return -1; }
    memcpy(A, in, u * sizeof(uint16_t));
    memcpy(B, in + u, v * sizeof(uint16_t));
    size_t lenA = u, lenB = v;

    int start = decrypt ? 9 : 0;
    int end = decrypt ? -1 : 10;
    int step = decrypt ? -1 : 1;

    for (int round = start; round != end; round += step) {
        const uint16_t *qdigits = decrypt ? A : B;
        size_t qlen = decrypt ? lenA : lenB;

        BIGNUM *numQ = digits_to_bn(qdigits, qlen, radix);
        if (!numQ) goto fail;

        size_t pad = (16 - ((t + 1 + b) % 16)) % 16;
        size_t qbytes = t + pad + 1 + b;
        uint8_t *Q = calloc(qbytes, 1);
        if (!Q) { BN_free(numQ); goto fail; }
        memcpy(Q, tweak, t);
        Q[t + pad] = (uint8_t)round;
        if (BN_bn2binpad(numQ, Q + t + pad + 1, (int)b) != (int)b) {
            BN_free(numQ); free(Q); goto fail;
        }
        BN_free(numQ);

        size_t pq_len = 16 + qbytes;
        uint8_t *PQ = malloc(pq_len);
        if (!PQ) { free(Q); goto fail; }
        memcpy(PQ, P, 16);
        memcpy(PQ + 16, Q, qbytes);
        free(Q);

        uint8_t R[16];
        if (ff1_prf(key, PQ, pq_len, R) != 0) { free(PQ); goto fail; }
        free(PQ);

        uint8_t *S = malloc(d);
        if (!S) goto fail;
        size_t copied = d < 16 ? d : 16;
        memcpy(S, R, copied);
        size_t soff = copied;
        uint32_t j = 1;
        while (soff < d) {
            uint8_t ctr[16] = {0}, x[16], z[16];
            ctr[12] = (uint8_t)(j >> 24);
            ctr[13] = (uint8_t)(j >> 16);
            ctr[14] = (uint8_t)(j >> 8);
            ctr[15] = (uint8_t)j;
            xor16(x, R, ctr);
            if (aes256_block(key, x, z) != 0) { free(S); goto fail; }
            size_t take = (d - soff < 16) ? d - soff : 16;
            memcpy(S + soff, z, take);
            soff += take;
            j++;
        }

        BIGNUM *y = BN_bin2bn(S, (int)d, NULL);
        free(S);
        if (!y) goto fail;

        size_t m = (round % 2 == 0) ? u : v;
        BIGNUM *mod = BN_new(), *base = BN_new(), *expm = BN_new();
        if (!mod || !base || !expm) { BN_free(y); BN_free(mod); BN_free(base); BN_free(expm); goto fail; }
        BN_set_word(base, radix);
        BN_set_word(expm, (BN_ULONG)m);
        if (!BN_exp(mod, base, expm, bnctx)) {
            BN_free(y); BN_free(mod); BN_free(base); BN_free(expm); goto fail;
        }
        BN_free(base); BN_free(expm);

        BIGNUM *src = digits_to_bn(decrypt ? B : A, m, radix);
        BIGNUM *res = BN_new();
        if (!src || !res) { BN_free(y); BN_free(mod); BN_free(src); BN_free(res); goto fail; }

        if (!decrypt) {
            if (!BN_mod_add(res, src, y, mod, bnctx)) {
                BN_free(y); BN_free(mod); BN_free(src); BN_free(res); goto fail;
            }
        } else {
            if (!BN_mod_sub(res, src, y, mod, bnctx)) {
                BN_free(y); BN_free(mod); BN_free(src); BN_free(res); goto fail;
            }
        }
        BN_free(y); BN_free(mod); BN_free(src);

        if (bn_to_digits(res, C, m, radix) != 0) { BN_free(res); goto fail; }
        BN_free(res);

        if (!decrypt) {
            memcpy(A, B, lenB * sizeof(uint16_t));
            lenA = lenB;
            memcpy(B, C, m * sizeof(uint16_t));
            lenB = m;
        } else {
            memcpy(B, A, lenA * sizeof(uint16_t));
            lenB = lenA;
            memcpy(A, C, m * sizeof(uint16_t));
            lenA = m;
        }
    }

    if (lenA + lenB != n) goto fail;
    memcpy(out, A, lenA * sizeof(uint16_t));
    memcpy(out + lenA, B, lenB * sizeof(uint16_t));
    free(A); free(B); free(C); BN_CTX_free(bnctx);
    return 0;

fail:
    free(A); free(B); free(C); BN_CTX_free(bnctx);
    return -1;
}

/* ------------------------------------------------------------------
 * ML-KEM representation helpers
 * ------------------------------------------------------------------ */

static int unpack_bits(const uint8_t *in, size_t in_len, unsigned d,
                       uint16_t *out, size_t count)
{
    uint64_t acc = 0;
    unsigned bits = 0;
    size_t pos = 0;
    uint32_t mask = (1u << d) - 1u;
    for (size_t i = 0; i < count; i++) {
        while (bits < d) {
            if (pos >= in_len) return -1;
            acc |= ((uint64_t)in[pos++]) << bits;
            bits += 8;
        }
        out[i] = (uint16_t)(acc & mask);
        acc >>= d;
        bits -= d;
    }
    return 0;
}

static int pack_bits(const uint16_t *in, size_t count, unsigned d,
                     uint8_t *out, size_t out_len)
{
    memset(out, 0, out_len);
    uint64_t acc = 0;
    unsigned bits = 0;
    size_t pos = 0;
    uint32_t mask = (1u << d) - 1u;
    for (size_t i = 0; i < count; i++) {
        if (in[i] > mask) return -1;
        acc |= ((uint64_t)in[i]) << bits;
        bits += d;
        while (bits >= 8) {
            if (pos >= out_len) return -1;
            out[pos++] = (uint8_t)(acc & 0xffu);
            acc >>= 8;
            bits -= 8;
        }
    }
    if (bits) {
        if (pos >= out_len) return -1;
        out[pos++] = (uint8_t)(acc & 0xffu);
    }
    return pos == out_len ? 0 : -1;
}

static uint16_t decompress_d(uint16_t y, unsigned d)
{
    return (uint16_t)(((uint32_t)MLKEM_Q * y + (1u << (d - 1))) >> d);
}

static uint16_t compress_d(uint16_t x, unsigned d)
{
    uint32_t v = (((uint32_t)x << d) + MLKEM_Q / 2) / MLKEM_Q;
    return (uint16_t)(v & ((1u << d) - 1u));
}

static int ctr_mask_32(const uint8_t hp[32], const char *label,
                       const uint8_t in[32], uint8_t out[32])
{
    uint8_t key[32], iv[16] = {0};
    SHA256_CTX h;
    SHA256_Init(&h);
    SHA256_Update(&h, label, strlen(label));
    SHA256_Update(&h, hp, 32);
    SHA256_Final(key, &h);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0, ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, out, &len, in, 32) != 1) goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) goto done;
    total += len;
    ok = (total == 32);
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int MaskPK_Enc(const uint8_t hp[32],
                      const uint8_t pk[KEM_PK_BYTES],
                      uint8_t C1[C1_BYTES])
{
    uint16_t x[PK_COEFFS], y[PK_COEFFS];
    if (unpack_bits(pk, PK_COEFF_BYTES, 12, x, PK_COEFFS) != 0) return -1;
    for (size_t i = 0; i < PK_COEFFS; i++) if (x[i] >= MLKEM_Q) return -1;
    const uint8_t tweak[] = "MaskPK-q3329";
    if (ff1_q_crypt(hp, tweak, sizeof(tweak)-1, x, y, PK_COEFFS, 0) != 0) return -1;
    if (pack_bits(y, PK_COEFFS, 12, C1, PK_COEFF_BYTES) != 0) return -1;
    if (ctr_mask_32(hp, "MaskPK-rho", pk + PK_COEFF_BYTES, C1 + PK_COEFF_BYTES) != 0) return -1;
    return 0;
}

static int MaskPK_Dec(const uint8_t hp[32],
                      const uint8_t C1[C1_BYTES],
                      uint8_t pk[KEM_PK_BYTES])
{
    uint16_t x[PK_COEFFS], y[PK_COEFFS];
    if (unpack_bits(C1, PK_COEFF_BYTES, 12, x, PK_COEFFS) != 0) return -1;
    for (size_t i = 0; i < PK_COEFFS; i++) if (x[i] >= MLKEM_Q) return -1;
    const uint8_t tweak[] = "MaskPK-q3329";
    if (ff1_q_crypt(hp, tweak, sizeof(tweak)-1, x, y, PK_COEFFS, 1) != 0) return -1;
    if (pack_bits(y, PK_COEFFS, 12, pk, PK_COEFF_BYTES) != 0) return -1;
    if (ctr_mask_32(hp, "MaskPK-rho", C1 + PK_COEFF_BYTES, pk + PK_COEFF_BYTES) != 0) return -1;
    return 0;
}

static int MaskCT_Enc(const uint8_t hp[32],
                      const uint8_t ct[KEM_CT_BYTES],
                      uint8_t C2[C2_BYTES])
{
    uint16_t enc_u[CT_U_COEFFS], enc_v[CT_V_COEFFS];
    uint16_t qx[CT_Q_COEFFS], qy[CT_Q_COEFFS];

    if (unpack_bits(ct, CT_U_BYTES, 10, enc_u, CT_U_COEFFS) != 0) return -1;
    if (unpack_bits(ct + CT_U_BYTES, CT_V_BYTES, 4, enc_v, CT_V_COEFFS) != 0) return -1;

    for (size_t i = 0; i < CT_U_COEFFS; i++) qx[i] = decompress_d(enc_u[i], 10);
    for (size_t i = 0; i < CT_V_COEFFS; i++) qx[CT_U_COEFFS + i] = decompress_d(enc_v[i], 4);

    const uint8_t tweak[] = "MaskCT-q3329";
    if (ff1_q_crypt(hp, tweak, sizeof(tweak)-1, qx, qy, CT_Q_COEFFS, 0) != 0) return -1;
    return pack_bits(qy, CT_Q_COEFFS, 12, C2, C2_BYTES);
}

static int MaskCT_Dec(const uint8_t hp[32],
                      const uint8_t C2[C2_BYTES],
                      uint8_t ct[KEM_CT_BYTES])
{
    uint16_t qx[CT_Q_COEFFS], qy[CT_Q_COEFFS];
    uint16_t enc_u[CT_U_COEFFS], enc_v[CT_V_COEFFS];

    if (unpack_bits(C2, C2_BYTES, 12, qx, CT_Q_COEFFS) != 0) return -1;
    for (size_t i = 0; i < CT_Q_COEFFS; i++) if (qx[i] >= MLKEM_Q) return -1;

    const uint8_t tweak[] = "MaskCT-q3329";
    if (ff1_q_crypt(hp, tweak, sizeof(tweak)-1, qx, qy, CT_Q_COEFFS, 1) != 0) return -1;

    for (size_t i = 0; i < CT_U_COEFFS; i++) enc_u[i] = compress_d(qy[i], 10);
    for (size_t i = 0; i < CT_V_COEFFS; i++) enc_v[i] = compress_d(qy[CT_U_COEFFS + i], 4);

    if (pack_bits(enc_u, CT_U_COEFFS, 10, ct, CT_U_BYTES) != 0) return -1;
    if (pack_bits(enc_v, CT_V_COEFFS, 4, ct + CT_U_BYTES, CT_V_BYTES) != 0) return -1;
    return 0;
}

/* ------------------------------------------------------------------
 * ML-KEM wrappers
 * ------------------------------------------------------------------ */

static int KEM_KeyGen(uint8_t pk[KEM_PK_BYTES], uint8_t sk[KEM_SK_BYTES])
{
    return OQS_KEM_keypair(g_kem, pk, sk) == OQS_SUCCESS ? 0 : -1;
}

static int KEM_Encap(const uint8_t pk[KEM_PK_BYTES],
                     uint8_t ct[KEM_CT_BYTES],
                     uint8_t ss[KEM_SS_BYTES])
{
    return OQS_KEM_encaps(g_kem, ct, ss, pk) == OQS_SUCCESS ? 0 : -1;
}

static int KEM_Decap(const uint8_t sk[KEM_SK_BYTES],
                     const uint8_t ct[KEM_CT_BYTES],
                     uint8_t ss[KEM_SS_BYTES])
{
    return OQS_KEM_decaps(g_kem, ss, ct, sk) == OQS_SUCCESS ? 0 : -1;
}

/* ------------------------------------------------------------------
 * PPS serialization
 * ------------------------------------------------------------------ */

static void pps_serialize(const PPSRecord *r, uint8_t out[PPS_RECORD_BYTES])
{
    size_t off = 0;
    memcpy(out + off, r->salt, PPS_SALT_BYTES); off += PPS_SALT_BYTES;
    memcpy(out + off, r->nonce, AE_NONCE_BYTES); off += AE_NONCE_BYTES;
    memcpy(out + off, r->hL, PPS_BIND_BYTES); off += PPS_BIND_BYTES;
    memcpy(out + off, r->enc_dk, PPS_CT_BYTES); off += PPS_CT_BYTES;
    memcpy(out + off, r->tag, AE_TAG_BYTES); off += AE_TAG_BYTES;
    memcpy(out + off, r->suite, PPS_SUITE_BYTES); off += PPS_SUITE_BYTES;
    memcpy(out + off, r->ver, PPS_VER_BYTES);
}

static void pps_deserialize(const uint8_t in[PPS_RECORD_BYTES], PPSRecord *r)
{
    size_t off = 0;
    memcpy(r->salt, in + off, PPS_SALT_BYTES); off += PPS_SALT_BYTES;
    memcpy(r->nonce, in + off, AE_NONCE_BYTES); off += AE_NONCE_BYTES;
    memcpy(r->hL, in + off, PPS_BIND_BYTES); off += PPS_BIND_BYTES;
    memcpy(r->enc_dk, in + off, PPS_CT_BYTES); off += PPS_CT_BYTES;
    memcpy(r->tag, in + off, AE_TAG_BYTES); off += AE_TAG_BYTES;
    memcpy(r->suite, in + off, PPS_SUITE_BYTES); off += PPS_SUITE_BYTES;
    memcpy(r->ver, in + off, PPS_VER_BYTES);
}

/* ------------------------------------------------------------------
 * Protocol
 * ------------------------------------------------------------------ */

static int Registration(const char *C, const char *S,
                        const char *pw, ServerRecord *rec)
{
    memset(rec, 0, sizeof(*rec));
    uint8_t dkL[KEM_SK_BYTES];

    if (KEM_KeyGen(rec->ekL, dkL) != 0) return -1;
    H0_hp(pw, rec->hp);
    H_bind(rec->ekL, rec->pps.hL);

    rec->pps.suite[0] = 0x00; rec->pps.suite[1] = 0x01;
    rec->pps.ver[0] = 0x00; rec->pps.ver[1] = 0x01;
    if (random_bytes(rec->pps.salt, PPS_SALT_BYTES) != 0) return -1;
    if (random_bytes(rec->pps.nonce, AE_NONCE_BYTES) != 0) return -1;

    uint8_t Kst[AE_KEY_BYTES];
    if (derive_Kst(C, S, pw, &rec->pps, Kst) != 0) return -1;

    uint8_t aad[128];
    size_t aad_len = build_pps_aad(C, S, &rec->pps, aad, sizeof(aad));
    if (!aad_len) return -1;

    int rc = gcm_encrypt_explicit(Kst, rec->pps.nonce, aad, aad_len,
                                  dkL, KEM_SK_BYTES,
                                  rec->pps.enc_dk, rec->pps.tag);
    OPENSSL_cleanse(Kst, sizeof(Kst));
    OPENSSL_cleanse(dkL, sizeof(dkL));
    return rc;
}

static int Client_Round1(const char *pw, ClientState *st,
                         uint8_t C1[C1_BYTES])
{
    memset(st, 0, sizeof(*st));
    if (KEM_KeyGen(st->eph_pk, st->eph_sk) != 0) return -1;
    H0_hp(pw, st->hp);
    if (MaskPK_Enc(st->hp, st->eph_pk, C1) != 0) return -1;
    memcpy(st->C1, C1, C1_BYTES);
    return 0;
}

static int Server_Round2(const char *C, const char *S,
                         const ServerRecord *rec,
                         const uint8_t C1[C1_BYTES],
                         uint8_t C2[C2_BYTES],
                         uint8_t psi[PSI_BYTES],
                         uint8_t server_ssk[LAMBDA_BYTES])
{
    uint8_t eph_pk[KEM_PK_BYTES];
    if (MaskPK_Dec(rec->hp, C1, eph_pk) != 0) return -1;

    uint8_t eph_ct[KEM_CT_BYTES], eph_ss[KEM_SS_BYTES];
    if (KEM_Encap(eph_pk, eph_ct, eph_ss) != 0) return -1;

    uint8_t KT[LAMBDA_BYTES];
    G_KT(C, S, eph_pk, eph_ct, eph_ss, KT);

    if (MaskCT_Enc(rec->hp, eph_ct, C2) != 0) return -1;

    uint8_t cL[KEM_CT_BYTES], KL[KEM_SS_BYTES];
    if (KEM_Encap(rec->ekL, cL, KL) != 0) return -1;

    uint8_t KA[AE_KEY_BYTES];
    H_A(C, S, C1, C2, KT, KA);

    uint8_t pps_bytes[PPS_RECORD_BYTES];
    pps_serialize(&rec->pps, pps_bytes);
    uint8_t psi_plain[PSI_PLAIN_BYTES];
    memcpy(psi_plain, cL, KEM_CT_BYTES);
    memcpy(psi_plain + KEM_CT_BYTES, pps_bytes, PPS_RECORD_BYTES);

    size_t aad_cap = strlen(C) + strlen(S) + C1_BYTES + C2_BYTES;
    uint8_t *aad = malloc(aad_cap);
    if (!aad) return -1;
    size_t aad_len = build_ctx_aad(C, S, C1, C2, aad, aad_cap);
    if (!aad_len) { free(aad); return -1; }

    if (AE_Enc_AAD(KA, aad, aad_len, psi_plain, PSI_PLAIN_BYTES,
                   psi, PSI_BYTES) != 0) {
        free(aad); return -1;
    }
    free(aad);

    uint8_t sid[LAMBDA_BYTES];
    H_sid(C, S, C1, C2, psi, sid);
    H_sk(sid, KT, KL, server_ssk);
    return 0;
}

static int Client_Finish(const char *C, const char *S, const char *pw,
                         ClientState *st,
                         const uint8_t C2[C2_BYTES],
                         const uint8_t psi[PSI_BYTES],
                         uint8_t client_ssk[LAMBDA_BYTES])
{
    uint8_t eph_ct[KEM_CT_BYTES];
    if (MaskCT_Dec(st->hp, C2, eph_ct) != 0) return -1;

    uint8_t eph_ss[KEM_SS_BYTES];
    if (KEM_Decap(st->eph_sk, eph_ct, eph_ss) != 0) return -1;

    uint8_t KT[LAMBDA_BYTES];
    G_KT(C, S, st->eph_pk, eph_ct, eph_ss, KT);
    memcpy(st->KT, KT, LAMBDA_BYTES);

    uint8_t KA[AE_KEY_BYTES];
    H_A(C, S, st->C1, C2, KT, KA);

    size_t aad_cap = strlen(C) + strlen(S) + C1_BYTES + C2_BYTES;
    uint8_t *aad = malloc(aad_cap);
    if (!aad) return -1;
    size_t aad_len = build_ctx_aad(C, S, st->C1, C2, aad, aad_cap);
    if (!aad_len) { free(aad); return -1; }

    uint8_t psi_plain[PSI_PLAIN_BYTES];
    if (AE_Dec_AAD(KA, aad, aad_len, psi, PSI_BYTES,
                   psi_plain, PSI_PLAIN_BYTES) != 0) {
        free(aad); return -1;
    }
    free(aad);

    uint8_t cL[KEM_CT_BYTES];
    PPSRecord pps;
    memcpy(cL, psi_plain, KEM_CT_BYTES);
    pps_deserialize(psi_plain + KEM_CT_BYTES, &pps);

    uint8_t Kst[AE_KEY_BYTES];
    if (derive_Kst(C, S, pw, &pps, Kst) != 0) return -1;

    uint8_t pps_aad[128];
    size_t pps_aad_len = build_pps_aad(C, S, &pps, pps_aad, sizeof(pps_aad));
    if (!pps_aad_len) return -1;

    uint8_t dkL[KEM_SK_BYTES];
    if (gcm_decrypt_explicit(Kst, pps.nonce, pps_aad, pps_aad_len,
                             pps.enc_dk, KEM_SK_BYTES, pps.tag, dkL) != 0) {
        OPENSSL_cleanse(Kst, sizeof(Kst));
        return -1;
    }
    OPENSSL_cleanse(Kst, sizeof(Kst));

    uint8_t KL[KEM_SS_BYTES];
    if (KEM_Decap(dkL, cL, KL) != 0) {
        OPENSSL_cleanse(dkL, sizeof(dkL));
        return -1;
    }
    OPENSSL_cleanse(dkL, sizeof(dkL));

    uint8_t sid[LAMBDA_BYTES];
    H_sid(C, S, st->C1, C2, psi, sid);
    H_sk(sid, KT, KL, client_ssk);
    return 0;
}

/* ------------------------------------------------------------------
 * Registration-record transport
 * ------------------------------------------------------------------ */

static int send_record(int fd, const ServerRecord *r)
{
    uint8_t pps[PPS_RECORD_BYTES];
    pps_serialize(&r->pps, pps);
    if (writen(fd, r->hp, LAMBDA_BYTES) != 0) return -1;
    if (writen(fd, r->ekL, KEM_PK_BYTES) != 0) return -1;
    if (writen(fd, pps, PPS_RECORD_BYTES) != 0) return -1;
    return 0;
}

static int recv_record(int fd, ServerRecord *r)
{
    uint8_t pps[PPS_RECORD_BYTES];
    if (readn(fd, r->hp, LAMBDA_BYTES) != 0) return -1;
    if (readn(fd, r->ekL, KEM_PK_BYTES) != 0) return -1;
    if (readn(fd, pps, PPS_RECORD_BYTES) != 0) return -1;
    pps_deserialize(pps, &r->pps);
    return 0;
}

/* ------------------------------------------------------------------
 * Server / client loops: same timing semantics as the baseline.
 * ------------------------------------------------------------------ */

static int run_server(int port, int measured_runs, int warmup_runs)
{
    const char *C = "Client-C";
    const char *S = "Server-S";
    int total_runs = measured_runs + warmup_runs;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_fd); return 1;
    }
    if (listen(listen_fd, 1) < 0) {
        perror("listen"); close(listen_fd); return 1;
    }

    printf("[SERVER] journal profile; port %d\n", port);
    fflush(stdout);

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    if (fd < 0) { perror("accept"); close(listen_fd); return 1; }
    set_tcp_nodelay(fd);

    BenchParams bp = {
        .measured_runs = measured_runs,
        .warmup_runs = warmup_runs,
        .c1_bytes = C1_BYTES,
        .c2_bytes = C2_BYTES,
        .psi_bytes = PSI_BYTES,
        .total_login_bytes = TOTAL_LOGIN_BYTES
    };
    if (writen(fd, &bp, sizeof(bp)) != 0) {
        close(fd); close(listen_fd); return 1;
    }

    ServerRecord rec;
    if (recv_record(fd, &rec) != 0) {
        fprintf(stderr, "registration record receive failed\n");
        close(fd); close(listen_fd); return 1;
    }

    printf("run,server_round2_ns\n");
    fflush(stdout);

    int mismatch = 0;
    for (int i = 0; i < total_runs; i++) {
        uint8_t C1[C1_BYTES], C2[C2_BYTES], psi[PSI_BYTES];
        uint8_t server_ssk[LAMBDA_BYTES], client_ssk[LAMBDA_BYTES];

        if (readn(fd, C1, C1_BYTES) != 0) break;

        uint64_t t0 = now_ns();
        if (Server_Round2(C, S, &rec, C1, C2, psi, server_ssk) != 0) {
            fprintf(stderr, "Server_Round2 failed run=%d\n", i); break;
        }
        uint64_t t1 = now_ns();

        if (writen(fd, C2, C2_BYTES) != 0) break;
        if (writen(fd, psi, PSI_BYTES) != 0) break;
        if (readn(fd, client_ssk, LAMBDA_BYTES) != 0) break;
        if (memcmp(server_ssk, client_ssk, LAMBDA_BYTES) != 0) mismatch++;

        if (i >= warmup_runs) {
            printf("%d,%lu\n", i - warmup_runs,
                   (unsigned long)(t1 - t0));
            fflush(stdout);
        }
    }

    if (mismatch) fprintf(stderr, "[WARN] ssk mismatch=%d\n", mismatch);
    else fprintf(stderr, "[OK] all measured protocol runs matched session keys\n");

    close(fd);
    close(listen_fd);
    return 0;
}

static int run_client(const char *server_ip, int port,
                      int measured_runs, int warmup_runs)
{
    const char *C = "Client-C";
    const char *S = "Server-S";
    const char *pw = "correct horse battery staple";
    (void)measured_runs; (void)warmup_runs;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &serv.sin_addr) != 1) {
        close(fd); return 1;
    }
    if (connect(fd, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
        perror("connect"); close(fd); return 1;
    }
    set_tcp_nodelay(fd);

    BenchParams bp;
    if (readn(fd, &bp, sizeof(bp)) != 0) { close(fd); return 1; }
    int m_runs = bp.measured_runs, w_runs = bp.warmup_runs;
    int total_runs = m_runs + w_runs;

    fprintf(stderr,
            "[JOURNAL] C1=%d C2=%d PSI=%d total=%d B; "
            "PPS=%d B; Argon2id m=%dKiB t=%d p=%d\n",
            bp.c1_bytes, bp.c2_bytes, bp.psi_bytes, bp.total_login_bytes,
            PPS_RECORD_BYTES, ARGON2_M_COST_KIB, ARGON2_T_COST,
            ARGON2_PARALLELISM);

    ServerRecord rec;
    if (Registration(C, S, pw, &rec) != 0) {
        fprintf(stderr, "Registration failed\n"); close(fd); return 1;
    }
    if (send_record(fd, &rec) != 0) {
        fprintf(stderr, "registration send failed\n"); close(fd); return 1;
    }

    printf("run,client_round1_ns,net_rtt_ns,client_finish_ns,total_login_ns\n");
    fflush(stdout);

    int fail = 0;
    for (int i = 0; i < total_runs; i++) {
        ClientState st;
        uint8_t C1[C1_BYTES], C2[C2_BYTES], psi[PSI_BYTES];
        uint8_t client_ssk[LAMBDA_BYTES];

        uint64_t t0 = now_ns();
        if (Client_Round1(pw, &st, C1) != 0) break;
        uint64_t t1 = now_ns();

        if (writen(fd, C1, C1_BYTES) != 0) break;
        if (readn(fd, C2, C2_BYTES) != 0) break;
        if (readn(fd, psi, PSI_BYTES) != 0) break;
        uint64_t t2 = now_ns();

        if (Client_Finish(C, S, pw, &st, C2, psi, client_ssk) != 0) {
            fprintf(stderr, "Client_Finish failed run=%d\n", i);
            fail++; break;
        }
        uint64_t t3 = now_ns();

        if (writen(fd, client_ssk, LAMBDA_BYTES) != 0) break;

        if (i >= w_runs) {
            printf("%d,%lu,%lu,%lu,%lu\n",
                   i - w_runs,
                   (unsigned long)(t1 - t0),
                   (unsigned long)(t2 - t1),
                   (unsigned long)(t3 - t2),
                   (unsigned long)(t3 - t0));
            fflush(stdout);
        }
    }

    if (fail) fprintf(stderr, "[WARN] finish failures=%d\n", fail);
    close(fd);
    return fail ? 1 : 0;
}

static int init_kem(void)
{
    g_kem = OQS_KEM_new(KEM_ALG);
    if (!g_kem) return -1;
    if (g_kem->length_public_key != KEM_PK_BYTES ||
        g_kem->length_secret_key != KEM_SK_BYTES ||
        g_kem->length_ciphertext != KEM_CT_BYTES ||
        g_kem->length_shared_secret != KEM_SS_BYTES) {
        OQS_KEM_free(g_kem); g_kem = NULL;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (init_kem() != 0) {
        fprintf(stderr, "ML-KEM-768 initialization failed\n");
        return 1;
    }

    int ret = 0;
    if (argc < 2) {
        printf("usage:\n");
        printf("  %s server [port] [measured_runs] [warmup_runs]\n", argv[0]);
        printf("  %s client [server_ip] [port] [measured_runs] [warmup_runs]\n", argv[0]);
        printf("journal sizes: C1=%d C2=%d PPS=%d PSI=%d total=%d bytes\n",
               C1_BYTES, C2_BYTES, PPS_RECORD_BYTES, PSI_BYTES, TOTAL_LOGIN_BYTES);
        printf("Argon2id: m=%d KiB t=%d p=%d\n",
               ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_PARALLELISM);
    } else if (strcmp(argv[1], "server") == 0) {
        int port = argc > 2 ? atoi(argv[2]) : 8080;
        int m = argc > 3 ? atoi(argv[3]) : 1000;
        int w = argc > 4 ? atoi(argv[4]) : 100;
        ret = run_server(port, m, w);
    } else if (strcmp(argv[1], "client") == 0) {
        const char *ip = argc > 2 ? argv[2] : "127.0.0.1";
        int port = argc > 3 ? atoi(argv[3]) : 8080;
        int m = argc > 4 ? atoi(argv[4]) : 1000;
        int w = argc > 5 ? atoi(argv[5]) : 100;
        ret = run_client(ip, port, m, w);
    } else {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        ret = 1;
    }

    if (g_kem) OQS_KEM_free(g_kem);
    return ret;
}
