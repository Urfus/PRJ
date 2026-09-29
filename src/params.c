#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>


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
