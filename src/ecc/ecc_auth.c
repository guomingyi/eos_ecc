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
static int privateToPublic(unsigned char *priv_key, unsigned char *pub_key); 
static int Base58Decode(uint8_t *in, uint8_t *out);

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz);
bool b58tobin(void *bin, size_t *binszp, const char *b58);
/***************************************************************************************/
static int privateToPublic(uint8_t *prik, uint8_t *pubk) 
{
    curve_point R;
    bignum256 k;
    uint8_t priv_key_raw[32];
    uint8_t pub_key[36+1];
    uint8_t hash[32];
    char b58_str[32+32] = {0};
    size_t res = sizeof(b58_str);

    Base58Decode(prik, priv_key_raw);
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

static int Base58Decode(uint8_t *in, uint8_t *out)
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
        printf("check error!");
        goto error;
    }

    memcpy(out, o + offset, key_len - offset);
    printf("%s: %s - success!\n",__func__, in);
    return 0;

error:
    return -1;
}


int main(void)
{
    uint8_t seed[] = "I love you so much!";
    uint8_t private_key[256] = "5HqctJyXzsaSybGYxJZnKAqVPPp73AXtDiVUQ95CStTLwiJuzik";
    uint8_t public_key[256] = {0};


    /** Base58Decode((uint8_t *)"6vJk3nfmQm16naqbTwphK2Li8Bdy1Nq2Y96bBmnUkjo5qe3G8B", public_key); */
    /** Base58Decode((uint8_t *)"5HqctJyXzsaSybGYxJZnKAqVPPp73AXtDiVUQ95CStTLwiJuzik", private_key); */
    /** return 0; */

    printf("\nseed:%s\n", seed);

    privateToPublic(private_key, public_key);
    PRINTF_ARRAY("public key", public_key, 33);

    return 0;
}


