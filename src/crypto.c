#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/string.h>
#include <crypto/skcipher.h>

#include "../inc/crypto.h"
#include "../inc/crypt_drv.h"

static const char *algo_names[] = {
    "ecb(aes)",      // индекс 0
    "chacha20",      // индекс 1
    "des3_ede"       // индекс 2
};

struct crypto_ctx* drv_crypto_init(void)
{
    int ret;

    struct crypto_ctx *local_crypto_data = NULL;
    
    local_crypto_data = kzalloc(sizeof(*local_crypto_data), GFP_KERNEL);
    if (!local_crypto_data) {
        return NULL;
    }
    // значения по умолчанию для алгоритма и строки ключа
    local_crypto_data->crypto_alg = ALGO_AES;
   
    if (strscpy(local_crypto_data->key_str, "1234567890abcdef", sizeof(local_crypto_data->key_str)) < 0) {
        pr_err("default key string too long for buffer\n");
        kfree(local_crypto_data);
        return NULL;
    }

    local_crypto_data->ivsize = drv_crypto_ivsize(local_crypto_data);
    
    // Генерируем случайный IV для этого процесса
    if (local_crypto_data->ivsize > 0) {
        if (local_crypto_data->ivsize > MAX_IV_SIZE) {
            pr_err(DRV_NAME ": IV size %zu exceeds MAX_IV_SIZE %d\n",
                   local_crypto_data->ivsize, MAX_IV_SIZE);
            kfree(local_crypto_data);
            return NULL;
        }
        get_random_bytes(local_crypto_data->iv, local_crypto_data->ivsize);
    }

    local_crypto_data->tfm = crypto_alloc_skcipher(algo_names[local_crypto_data->crypto_alg], 0, 0);
    if (IS_ERR(local_crypto_data->tfm)) {
        pr_err(DRV_NAME ": Failed to alloc crypto %s\n", algo_names[local_crypto_data->crypto_alg]);
        kfree(local_crypto_data);
        return NULL;
    }

    ret = crypto_skcipher_setkey(local_crypto_data->tfm, local_crypto_data->key_str, strlen(local_crypto_data->key_str));
    if (ret) {
        pr_err(DRV_NAME ": Invalid key length for %s\n", algo_names[local_crypto_data->crypto_alg]);
        crypto_free_skcipher(local_crypto_data->tfm);
        kfree(local_crypto_data);
        return NULL;
    }

    pr_info(DRV_NAME ": Crypto initialized: algo=%s, blocksize=%u, ivsize=%u\n",
        algo_names[local_crypto_data->crypto_alg],
        crypto_skcipher_blocksize(local_crypto_data->tfm),
        crypto_skcipher_ivsize(local_crypto_data->tfm));

    return local_crypto_data;
}

void drv_crypto_exit(struct crypto_ctx* ptr_crypto_ctx)
{
    if (ptr_crypto_ctx->tfm)
        crypto_free_skcipher(ptr_crypto_ctx->tfm);
}

size_t drv_crypto_blocksize(struct crypto_ctx* ptr_crypto_ctx)
{
    if (!ptr_crypto_ctx->tfm) return 1;
    return crypto_skcipher_blocksize(ptr_crypto_ctx->tfm);
}

size_t drv_crypto_ivsize(struct crypto_ctx* ptr_crypto_ctx)
{
    if (!ptr_crypto_ctx->tfm) return 0;
    return crypto_skcipher_ivsize(ptr_crypto_ctx->tfm);
}

int drv_do_crypto(struct crypto_ctx* ptr_crypto_ctx, char *buf, size_t len, int encrypt, u8 *iv)
{
   
    struct skcipher_request *req;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;

    if (!ptr_crypto_ctx->tfm || len == 0) return 0;

    req = skcipher_request_alloc(ptr_crypto_ctx->tfm, GFP_KERNEL);
    if (!req) {
        pr_err(DRV_NAME ": Failed to allocate skcipher request\n");
        return -ENOMEM;
    }
    pr_info(DRV_NAME ": (0) do_crypto\n");

    if (!req) return -ENOMEM;

    sg_init_one(&sg, buf, len);
    skcipher_request_set_crypt(req, &sg, &sg, len, ptr_crypto_ctx->ivsize > 0 ? iv : NULL);
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