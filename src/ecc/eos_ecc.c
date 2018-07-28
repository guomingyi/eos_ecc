#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "ripemd160.h"

extern const ecdsa_curve secp256k1;
static int compute_public_key(unsigned char *priv_key, unsigned char *pub_key); 
static int Base58_decode(uint8_t *out, uint8_t *in);
static int private_key_from_seed(uint8_t *seed, uint8_t *pk);

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
bool b58tobin(void *bin, size_t *binszp, const char *b58);
/***************************************************************************************/
static int compute_public_key(uint8_t *prik, uint8_t *pubk) 
{
    curve_point R;
    bignum256 k;
    uint8_t r[32];
    uint8_t pub_key[36+1];
    uint8_t hash[32];
    char b58_str[32+32] = {0};
    size_t res = sizeof(b58_str);

    Base58_decode(r, prik);
    bn_read_be(r, &k);
    // compute k*G
    scalar_multiply(&secp256k1, &k, &R);
    pub_key[0] = 0x02 | (R.y.val[0] & 0x01);
    bn_write_be(&R.x, pub_key + 1);

    ripemd160((const uint8_t *)pub_key, 32 + 1, hash);
    memcpy(pub_key + 32 + 1, hash, 4);

    b58enc(b58_str, &res, pub_key, sizeof(pub_key));
    int c = sprintf((char *)pubk, "EOS%s", b58_str);

    printf("ecc key:\n%s\n%s\n", (char *)prik,(char *)pubk);
    return c;
}

void PRINTF_ARRAY(char *tag, uint8_t *p, int len)
{
    printf("%s(%d):\n", tag, len);
    for (int i = 0; i < len; i++) {
        printf("0x%x,", p[i]);
    }
    printf("\n\n");
}

static int Base58_decode(uint8_t *out, uint8_t *in)
{
    uint8_t check[4] = {0};
    uint8_t hash[32 + 32] = {0};
    uint8_t d[36 + 4] = {0};
    uint8_t o[36] = {0};
    size_t res = (36 + 4);
    const int key_len = 33;
    int offset = 0;

    if (b58tobin(d, &res, (const void *)in) != true) {
        goto error;
    }

    memcpy(o, d + 3, key_len);
    memcpy(check, d + 36, 4);

    if ((d[3] & 0x80)) {
        // private key.
        hasher_Raw(HASHER_SHA2, o, key_len, hash + 32);
        hasher_Raw(HASHER_SHA2, hash + 32, 32, hash);
        offset = 1;
    }
    else {
        ripemd160((const uint8_t *)o, key_len, hash);
    }

    if (memcmp(check, hash, 4) != 0) {
        printf("%s: check error!", in);
        goto error;
    }

    memcpy(out, o + offset, key_len - offset);
    return 0;

error:
    return -1;
}

static int Base58_decode_sig(uint8_t *out, uint8_t *in)
{
    uint8_t check[4] = {0};
    uint8_t hash[32 + 32] = {0};
    uint8_t d[128] = {0};
    uint8_t o[128] = {0};
    size_t res = 70;

    if (b58tobin(d, &res, (const void *)in) != true) {
        goto error;
    }

    memcpy(o, d + 1, res - 4);
    memcpy(check, d + 1 + res - 4, 4);

    memcpy(o + strlen((char *)o), "K1", sizeof("K1"));
    ripemd160((const uint8_t *)o, strlen((char *)o), hash);

    if (memcmp(check, hash, 4) != 0) {
        printf("%s: check error!", in);
        goto error;
    }

    memcpy(out, o, strlen((char *)o) - 2);
    return 0;

error:
    return -1;
}

static int private_key_from_seed(uint8_t *seed, uint8_t *pk) 
{
    uint8_t a = 0x80;
    uint8_t hash[32+32];
    uint8_t priv_key[33];
    uint8_t buf[33 + 4];
    char b58_str[64] = {0};
    int seed_len;

    printf("seed:%s\n", seed);

    seed_len = strlen((char *)seed);
    hasher_Raw(HASHER_SHA2, seed, seed_len, priv_key + 1);
    priv_key[0] = a;

    hasher_Raw(HASHER_SHA2, priv_key, 33, hash + 32);
    hasher_Raw(HASHER_SHA2, hash + 32, 32, hash);

    memcpy(buf, priv_key, 33);
    memcpy(buf + 33, hash, 4);

    size_t res = sizeof(b58_str);
    if (b58enc(b58_str, &res, (const char *)buf, sizeof(buf))) {
        memcpy(pk, b58_str, strlen(b58_str));
        return 0;
    }
    return -1;
}

static int ecc_pub_recovery(uint8_t *pub_key, uint8_t *sig, uint8_t *digest)
{
    uint8_t recid = (sig[0] - 27) % 4;
    bool compressed = sig[0] >= 31;

    if (ecdsa_verify_digest_recover(&secp256k1, pub_key, sig + 1, digest, recid) != 0) {
        return -1;
    }
    // convert public key to compressed pubkey if necessary
    if (compressed) {
        pub_key[0] = 0x02 | (pub_key[64] & 1);
    }
    return 0;
}

static int ecc_sign(uint8_t *priv_key, uint8_t *msg, uint8_t *sig)
{
    curve_point R;
    bignum256 k;

    uint8_t d[32];
    uint8_t r[33] = {0};
    uint8_t s[80] = {0};
    uint8_t hash[32] = {0};
    uint8_t buf[128] = {0};
    uint8_t recv_id = 0;
    int n;

    n = strlen((char *)msg);
    hasher_Raw(HASHER_SHA2, msg, n, d);
    Base58_decode(r, priv_key);
    bn_read_be(r, &k);
    // compute k*G
    scalar_multiply(&secp256k1, &k, &R);

    if (ecdsa_sign_digest(&secp256k1, r, d, s + 1, &recv_id, NULL) < 0) {
        goto err;
    }

    s[0] = recv_id; // pub key recovery id.
    s[0] += 4; // compressed
    s[0] += 27; // forcing odd-y 2nd key candidate

    memcpy(s + strlen((char *)s), "K1", sizeof("K1"));
    int c = strlen((char *)s);
    ripemd160((const uint8_t *)s, c, hash);
    memcpy(s + c - 2, hash, 4); // "K1" only for gen check hash, check num: hash[0,3].

    size_t res = sizeof(buf);
    if (b58enc((char *)buf, &res, (const char *)s, strlen((char *)s))) {
        int c1 = sprintf((char *)sig, "SIG_K1_%s", buf);
        printf("%s:\nmsg: %s\n%s\n",__func__, msg, sig);
        return c1;
    }
err:
    printf("%s: sign err!\n",__func__);
    return -1;
}

static int ecc_verify(uint8_t *pub_key, uint8_t *sig, uint8_t *msg)
{
    uint8_t d[32];
    uint8_t r[33];
    uint8_t t[128] = {0};
    uint8_t s[128] = {0};
    int n = strlen((char *)msg);


    hasher_Raw(HASHER_SHA2, msg, n, d);
    memcpy(t, pub_key + 3, strlen((char *)pub_key) - 3); // cut 'EOS'
    Base58_decode(r, t);
    int h_len = strlen("SIG_K1_");
    memset(t, 0, sizeof(t));
    memcpy(t, sig + h_len, strlen((char *)sig) - h_len);
    Base58_decode_sig(s, t);
    if (ecdsa_verify_digest(&secp256k1, r, s + 1, d) != 0) {
        goto failed;
    }

    uint8_t rev[65] = {0};
    if (!((ecc_pub_recovery(rev, s, d) == 0) && (memcmp(r, rev, 33) == 0))) {
        goto failed;
    }

    printf("%s: signture verify success!\n",__func__);
    return 0;

failed:
    printf("%s: SIG VERIFY FAILED!\n",__func__);
    return -1;
}

int main(void)
{
    uint8_t seed[] = "[莫愁前路无知己]";
    uint8_t *msg = (uint8_t *)"[天下谁人不识君]";
    uint8_t private_key[76] = {0}; //"5KfAkHSi7dFemXxNYC4Vqnkj8d3F2xR46345MQa2V7BJizcviUx"
    uint8_t public_key[76] = {0}; // "EOS55tZ24kd1ivokihWK7Z9YJe3gup5yW6UiJMGkRbENGMYzeKgLC"
    uint8_t sig[128] = {0}; // "SIG_K1_KrxdP6J3oWdzyL2FywhtW6anbsiWfse2yfg83sgvURkwCucRNgtYcumTt7mzBey3gEjY79cwYsVitB2g9cGy2o4zJ1ELfS"

    private_key_from_seed(seed, private_key);
    compute_public_key(private_key, public_key);
    if (ecc_sign(private_key, msg, sig) < 0) {
        return -1;
    }
    ecc_verify(public_key, sig, msg);
    return 0;
}


