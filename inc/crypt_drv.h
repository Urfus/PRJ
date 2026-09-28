#ifndef CRYPT_DRV_H
#define CRYPT_DRV_H

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mutex.h>

#include "../inc/queue.h"

#define DRV_NAME "crypt_drv"
#define IOCTL_SET_MODE _IOW('D', 1, int)

#define MAX_IV_SIZE 32

enum my_crypto_type {
    ALGO_AES      = 0,
    ALGO_CHACHA   = 1,
    ALGO_DES      = 2,
};

enum my_crypto_mode {
    MODE_ENCRYPT = 0,
    MODE_DECRYPT = 1
};

struct proc_ctx {
    struct ring_buffer *rb;
    struct mutex lock;
    int mode;

    u8 iv[MAX_IV_SIZE];        // "Эталонный" IV для этого процесса
    size_t ivsize;             // Размер IV (0 для ECB)

};


extern int max_length;
extern enum my_crypto_type crypto_alg;
extern char *key_str;

#endif // CRYPT_DRV_H