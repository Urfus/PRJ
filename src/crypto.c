#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/string.h>
#include <crypto/skcipher.h>

#include "../inc/crypto.h"
#include "../inc/crypt_drv.h"

static struct crypto_skcipher *tfm = NULL;

static const char *algo_names[] = {
    "ecb(aes)",      // индекс 0
    "chacha20",      // индекс 1
    "des3_ede"       // индекс 2
};

int drv_crypto_init(void)
{
    int ret;

    tfm = crypto_alloc_skcipher(algo_names[crypto_alg], 0, 0);
    if (IS_ERR(tfm)) {
        pr_err(DRV_NAME ": Failed to alloc crypto %s\n", algo_names[crypto_alg]);
        return PTR_ERR(tfm);
    }

    ret = crypto_skcipher_setkey(tfm, key_str, strlen(key_str));
    if (ret) {
        pr_err(DRV_NAME ": Invalid key length for %s\n", algo_names[crypto_alg]);
        crypto_free_skcipher(tfm);
        return ret;
    }

    pr_info(DRV_NAME ": Crypto initialized: algo=%s, blocksize=%u, ivsize=%u\n",
        algo_names[crypto_alg],
        crypto_skcipher_blocksize(tfm),
        crypto_skcipher_ivsize(tfm));

    return 0;
}

void drv_crypto_exit(void)
{
    if (tfm)
        crypto_free_skcipher(tfm);
}

size_t drv_crypto_blocksize(void)
{
    if (!tfm) return 1;
    return crypto_skcipher_blocksize(tfm);
}

size_t drv_crypto_ivsize(void)
{
    if (!tfm) return 0;
    return crypto_skcipher_ivsize(tfm);
}

int drv_do_crypto(char *buf, size_t len, int encrypt, u8 *iv, size_t ivsize)
{
   
    struct skcipher_request *req;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;

    if (!tfm || len == 0) return 0;

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err(DRV_NAME ": Failed to allocate skcipher request\n");
        return -ENOMEM;
    }
    pr_info(DRV_NAME ": (0) do_crypto\n");

    if (!req) return -ENOMEM;

    sg_init_one(&sg, buf, len);
    skcipher_request_set_crypt(req, &sg, &sg, len, ivsize > 0 ? iv : NULL);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);

    if (encrypt)
        ret = crypto_skcipher_encrypt(req);
    else
        ret = crypto_skcipher_decrypt(req);

    pr_info(DRV_NAME ": (1) do_crypto ret = %d\n", ret);

    ret = crypto_wait_req(ret, &wait);
    pr_info(DRV_NAME ": (2) do_crypto ret = %d\n", ret);

    skcipher_request_free(req);

    return ret;
}

size_t add_pkcs7_padding(char *buf, size_t len, size_t capacity, size_t block_size)
{
    size_t pad_bytes, padded_len;
    char pad_value;

    if (block_size <= 1)
        return len;

    if (len == 0 || len > capacity)
        return 0;

    pad_bytes = block_size - (len % block_size);
    padded_len = len + pad_bytes;

    pr_info(DRV_NAME ": padding len = %zu, pad_bytes = %zu \n", len, pad_bytes);

    if (padded_len > capacity) {
        pr_err(DRV_NAME ": Not enough capacity for padding (%zu > %zu)\n",
               padded_len, capacity);
        return 0;
    }

    pad_value = (char)pad_bytes;
    memset(buf + len, pad_value, pad_bytes);

    pr_info(DRV_NAME ": Added %zu bytes of PKCS#7 padding (value=0x%02x)\n",
             pad_bytes, (unsigned char)pad_value);

    return padded_len;
}

size_t remove_pkcs7_padding(char *buf, size_t len)
{
    unsigned char pad_value;
    size_t i;

    if (len == 0)
        return 0;

    pad_value = (unsigned char)buf[len - 1];

    // Проверка валидности padding
    if (pad_value == 0 || pad_value > 16) {
        pr_warn(DRV_NAME ": Invalid PKCS#7 padding value: %u at len=%zu\n",
                pad_value, len);
        return len;
    }

    if (pad_value > len) {
        pr_warn(DRV_NAME ": Padding value %u exceeds length %zu\n",
                pad_value, len);
        return len;
    }
    for (i = 0; i < pad_value; i++) {
        if ((unsigned char)buf[len - 1 - i] != pad_value) {
            pr_warn(DRV_NAME ": Corrupted PKCS#7 padding at position %zu "
                    "(expected 0x%02x, got 0x%02x)\n",
                    len - 1 - i, pad_value, 
                    (unsigned char)buf[len - 1 - i]);
            return len;
        }
    }

    pr_debug(DRV_NAME ": Removed %u bytes of PKCS#7 padding\n", pad_value);
    return len - pad_value;
}