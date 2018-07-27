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
    uint8_t priv_key_raw[32];
    uint8_t pub_key[36+1];
    uint8_t hash[32];
    char b58_str[32+32] = {0};
    size_t res = sizeof(b58_str);

    Base58_decode(prik, priv_key_raw);
    bn_read_be(priv_key_raw, &k);
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

int main(void)
{
    uint8_t seed[] = "你好eos"; //"5KBGwdpPYgViff1wram2UnUCoU4eDK5eKTpZTBGRHCBgiPHF5o5"
    uint8_t private_key[76] = {0};
    uint8_t public_key[76] = {0};

    Seed_to_private_key(seed, private_key);
    Private_key_to_public_key(private_key, public_key);
    return 0;
}


