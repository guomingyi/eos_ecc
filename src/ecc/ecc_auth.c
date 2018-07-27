#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "ripemd160.h"

#define VERSION_PUBLIC  0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

extern const ecdsa_curve secp256k1;
static int Private_key_to_public_key(unsigned char *priv_key, unsigned char *pub_key); 
static int Base58_decode(uint8_t *in, uint8_t *out);
static int Seed_to_private_key(uint8_t *seed, uint8_t *pk);

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
bool b58tobin(void *bin, size_t *binszp, const char *b58);
/***************************************************************************************/
static int Private_key_to_public_key(uint8_t *prik, uint8_t *pubk) 
{
    curve_point R;
    bignum256 k;
    uint8_t r[32];
    uint8_t pub_key[36+1];
    uint8_t hash[32];
    char b58_str[32+32] = {0};
    size_t res = sizeof(b58_str);

    Base58_decode(prik, r);
    bn_read_be(r, &k);
    // compute k*G
    scalar_multiply(&secp256k1, &k, &R);
    pub_key[0] = 0x02 | (R.y.val[0] & 0x01);
    bn_write_be(&R.x, pub_key + 1);

    ripemd160((const uint8_t *)pub_key, 32 + 1, hash);
    memcpy(pub_key + 32 + 1, hash, 4);

    b58enc(b58_str, &res, pub_key, sizeof(pub_key));
    int c = sprintf((char *)pubk, "EOS%s", b58_str);

    printf("Private & Public key:\n%s\n%s\n", (char *)prik,(char *)pubk);
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

static int Base58_decode(uint8_t *in, uint8_t *out)
{
    uint8_t check[4] = {0};
    uint8_t hash[32 + 32] = {0};
    uint8_t d[36 + 4] = {0};
    uint8_t o[36] = {0};
    size_t res = sizeof(d);
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

static int Seed_to_private_key(uint8_t *seed, uint8_t *pk) 
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

static int ecc_sign(uint8_t *priv_key, uint8_t *msg, uint8_t *sig)
{
    curve_point R;
    bignum256 k;

    uint8_t d[32];
    uint8_t r[33] = {0};
    uint8_t s[80] = {0};
    uint8_t p;
    int n;

    n = strlen((char *)msg);
    hasher_Raw(HASHER_SHA2, msg, n, d);
    Base58_decode(priv_key, r);
    bn_read_be(r, &k);
    // compute k*G
    scalar_multiply(&secp256k1, &k, &R);

    ecdsa_sign_digest(&secp256k1, r, d, s, &p, NULL); 
    memcpy(sig, s, sizeof(s));
    return 0;
}

static int ecc_verify(uint8_t *pub_key, uint8_t *sig, uint8_t *msg) 
{
    uint8_t d[32];
    uint8_t r[33];
    uint8_t t[64] = {0};
    int n = strlen((char *)msg);

    hasher_Raw(HASHER_SHA2, msg, n, d);
    memcpy(t, pub_key + 3, strlen((char *)pub_key) - 3); // cut 'EOS'
    Base58_decode(t, r);
    int e = ecdsa_verify_digest(&secp256k1, r, sig, d);
    if (e != 0) {
        printf("%s: FAILED!!!.\n",__func__);
        return -1;
    }

    printf("%s: Success!\n",__func__);
    return 0;
}

int main(void)
{
    uint8_t seed[] = "你好eos"; 
    uint8_t private_key[76] = {0}; //"5KBGwdpPYgViff1wram2UnUCoU4eDK5eKTpZTBGRHCBgiPHF5o5"
    uint8_t public_key[76] = {0}; // "EOS8SGcitDFW42Dg19xgeG5AMARB7Y7ByrJ5RNapRG4J3V3d5wAs6"
    uint8_t sig[100] = {0};
    uint8_t *msg = (uint8_t *)"1234567890";

    Seed_to_private_key(seed, private_key);

    Private_key_to_public_key(private_key, public_key);

    ecc_sign(private_key, msg, sig);

    ecc_verify(public_key, sig, msg);
    return 0;
}


