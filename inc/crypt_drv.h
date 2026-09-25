#ifndef CRYPT_DRV_H
#define CRYPT_DRV_H

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mutex.h>

#include "../inc/queue.h"

#define DRV_NAME "crypt_drv"

struct proc_ctx {
    struct ring_buffer *rb;
    struct mutex lock;
};

enum my_crypto_type {
    ALGO_AES      = 0,
    ALGO_CHACHA   = 1,
    ALGO_DES      = 2,
};

enum my_crypto_mode {
    MODE_ENCRYPT = 0,
    MODE_DECRYPT = 1
};

extern int max_length;
extern enum my_crypto_type crypto_alg;
extern enum my_crypto_mode crypto_oper;
extern char *key_str;

#endif // CRYPT_DRV_H