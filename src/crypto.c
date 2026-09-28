#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/err.h>

#include "../inc/crypto.h"
#include "../inc/crypt_drv.h"

static struct crypto_skcipher *tfm = NULL;

static const char *algo_names[] = {
    "ctr(aes)",      // индекс 0
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

    return 0;
}

void drv_crypto_exit(void)
{
    if (tfm)
        crypto_free_skcipher(tfm);
}

int drv_do_crypto(char *buf, size_t len, int encrypt)
{
    return 0;
    
    struct skcipher_request *req;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int ret;

    if (!tfm || len == 0) return 0;

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    pr_info(DRV_NAME ": (0) do_crypto ret = %d\n", ret);

    if (!req) return -ENOMEM;

    sg_init_one(&sg, buf, len);
    skcipher_request_set_crypt(req, &sg, &sg, len, NULL);
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