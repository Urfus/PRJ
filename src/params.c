#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>


#include "../inc/params.h"
#include "../inc/crypt_drv.h"
#include "../inc/crypto.h"

// === max_length ===
static int param_set_max_length(const char *val, const struct kernel_param *kp)
{
    int tmp, ret;

    ret = kstrtoint(val, 0, &tmp);
    if (ret)
        return ret;

    if (tmp < 64 || tmp > 1048576) {
        pr_err(DRV_NAME ": max_length must be 64..1048576 (got %d)\n", tmp);
        return -EINVAL;
    }

    return param_set_int(val, kp);
}

static const struct kernel_param_ops max_length_ops = {
    .set = param_set_max_length,
    .get = param_get_int,
};

module_param_cb(max_length, &max_length_ops, &max_length, 0644);
MODULE_PARM_DESC(max_length, "Per-process buffer size in bytes (64..1048576, default 4096)");

// === crypto_type ===
static int param_set_crypto_type(const char *val, const struct kernel_param *kp)
{
    int tmp, ret;

    ret = kstrtoint(val, 0, &tmp);
    if (ret)
        return ret;

    if (tmp < 0 || tmp > 2) {
        pr_err(DRV_NAME ": Crypto_type must be 0..2,   ecb(aes) -> 0, chacha20 -> 1, des3_ede -> 2,(got %d)\n", tmp);
        return -EINVAL;
    }

    return param_set_int(val, kp);
}

static const struct kernel_param_ops crypto_algorithm_ops = {
    .set = param_set_crypto_type,
    .get = param_get_int,
};

module_param_cb(crypto_algorithm, &crypto_algorithm_ops, &crypto_alg, 0644);
MODULE_PARM_DESC(crypto_algorithm, "Crypto algorithm: 0 - ecb(aes), 1 - chacha20, 2 - des3_ede");

module_param(key_str, charp, 0444);
MODULE_PARM_DESC(key_str, "Symmetric encryption key");

void drv_params_init(void)
{
    pr_info(DRV_NAME ": param max_length = %d\n", max_length);
    pr_info(DRV_NAME ": crypto algorithm = %d\n", crypto_alg);
    pr_info(DRV_NAME ": symmetric encryption key = %s\n", key_str);
}

void drv_params_exit(void)
{
    /* зарезервировано для будущих ресурсов */
}



