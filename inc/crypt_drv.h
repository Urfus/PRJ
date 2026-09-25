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

extern int max_length;

#endif // CRYPT_DRV_H