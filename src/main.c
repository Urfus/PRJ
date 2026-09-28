#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include "../inc/crypt_drv.h"
#include "../inc/crypto.h"
#include "../inc/params.h"

int max_length = 4096;
enum my_crypto_type crypto_alg = ALGO_AES;

char *key_str = "1234567612635463";  // 16 byte

static int major;
static struct class *dev_class;
static struct device *dev;

static int drv_open(struct inode *inode, struct file *file)
{
    struct proc_ctx *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->rb = rb_init(max_length);
    if (!ctx->rb) {
        kfree(ctx);
        return -ENOMEM;
    }
    ctx->mode = MODE_ENCRYPT;

    mutex_init(&ctx->lock);

    // Получаем размер IV для текущего алгоритма
    ctx->ivsize = drv_crypto_ivsize();
    
    // Генерируем случайный IV для этого процесса
    if (ctx->ivsize > 0) {
        if (ctx->ivsize > MAX_IV_SIZE) {
            pr_err(DRV_NAME ": IV size %zu exceeds MAX_IV_SIZE %d\n",
                   ctx->ivsize, MAX_IV_SIZE);
            rb_free(ctx->rb);
            kfree(ctx);
            return -EINVAL;
        }
        get_random_bytes(ctx->iv, ctx->ivsize);
    }

    file->private_data = ctx;

    pr_info(DRV_NAME ": Device opened by PID %d (buffer %d bytes)\n", current->pid, max_length);
    return 0;
}

static int drv_release(struct inode *inode, struct file *file)
{
    struct proc_ctx *ctx = file->private_data;

    rb_free(ctx->rb);
    kfree(ctx);

    pr_info(DRV_NAME ": closed by PID %d\n", current->pid);
    return 0;

}


static ssize_t drv_write(struct file *file, const char __user *ubuf,
                         size_t count, loff_t *ppos)
{
    struct proc_ctx *ctx = file->private_data;
    char *kbuf;

    u8 iv_local[MAX_IV_SIZE];  // Локальная копия IV
    size_t written, crypto_len, final_len;
    size_t block_size;
    size_t alloc_size;

    int ret;

    if (!count)
        return 0;

    block_size = drv_crypto_blocksize();
    alloc_size = count + block_size;
    
    kbuf = kmalloc(alloc_size, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, ubuf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    pr_info(DRV_NAME ": PID %d write %zu bytes, mode=%s\n",
        current->pid, count,
        ctx->mode == MODE_ENCRYPT ? "ENCRYPT" : "DECRYPT");

    crypto_len = count;
    
    if (ctx->mode == MODE_ENCRYPT) {
        crypto_len = add_pkcs7_padding(kbuf, count, alloc_size, block_size);
        if (crypto_len == 0) {
            kfree(kbuf);
            return -EINVAL;
        }
    } else {
        if (block_size > 1 && (count % block_size) != 0) {
            pr_err(DRV_NAME ": DECRYPT mode requires length multiple of %zu "
                   "(got %zu)\n", block_size, count);
            kfree(kbuf);
            return -EINVAL;
        }
    }

    mutex_lock(&ctx->lock);
    if (ctx->ivsize > 0)
        memcpy(iv_local, ctx->iv, ctx->ivsize);

    pr_info(DRV_NAME ": write str = %.*s\n", (int) count, kbuf);

    ret = drv_do_crypto(kbuf, crypto_len, (ctx->mode == MODE_ENCRYPT), 
                        ctx->ivsize > 0 ? iv_local : NULL,
                        ctx->ivsize);
    pr_info(DRV_NAME ": str after do_crypto = %.*s\n", (int) count, kbuf);

    if (ret < 0) {
        pr_err(DRV_NAME ": error do_crypto  %d\n", ret);
        mutex_unlock(&ctx->lock);
        kfree(kbuf);
        return 0;
    }

    final_len = crypto_len;
    if (ctx->mode == MODE_DECRYPT) {
        final_len = remove_pkcs7_padding(kbuf, crypto_len);
    }

    written = rb_put(ctx->rb, kbuf, count);
    mutex_unlock(&ctx->lock);

    kfree(kbuf);
    return written ? (ssize_t)written : -ENOSPC;
}
    
static ssize_t drv_read(struct file *file, char __user *ubuf,
                        size_t count, loff_t *ppos)
{
    struct proc_ctx *ctx = file->private_data;
    char *kbuf;
    size_t nread;

    if (!count)
        return 0;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mutex_lock(&ctx->lock);
    nread = rb_get(ctx->rb, kbuf, count);
    mutex_unlock(&ctx->lock);

    if (!nread) {
        kfree(kbuf);
        return 0;
    }

    if (copy_to_user(ubuf, kbuf, nread)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return (ssize_t)nread;
}


static const struct file_operations drv_fops = {
    .owner   = THIS_MODULE,
    .open    = drv_open,
    .release = drv_release,
    .read    = drv_read,
    .write   = drv_write,
};

static int __init drv_init(void)
{

    int ret;

    ret = drv_crypto_init();
    if (ret) return ret;

    /* 1. Регистрация символьного устройства (динамический major) */
    major = register_chrdev(0, DRV_NAME, &drv_fops);
    if (major < 0) {
        pr_err(DRV_NAME ": Failed to register chrdev: %d\n", major);
        return major;
    }

    /* 2. Создание класса устройства (для udev) */
    dev_class = class_create(DRV_NAME);
    if (IS_ERR(dev_class)) {
        pr_err(DRV_NAME ": Failed to create class\n");
        unregister_chrdev(major, DRV_NAME);
        return PTR_ERR(dev_class);
    }

    /* 3. Создание узла /dev/crypt_drv */
    dev = device_create(dev_class, NULL, MKDEV(major, 0), NULL, DRV_NAME);
    if (IS_ERR(dev)) {
        pr_err(DRV_NAME ": Failed to create device\n");
        class_destroy(dev_class);
        unregister_chrdev(major, DRV_NAME);
        return PTR_ERR(dev);
    }

    pr_info(DRV_NAME ": Module loaded. Major: %d\n", major);
    pr_info(DRV_NAME ": param max_length = %d\n", max_length);
    pr_info(DRV_NAME ": crypto algorithm = %d\n", crypto_alg);
    pr_info(DRV_NAME ": symmetric encryption key = %s\n", key_str);

    return 0;
}

static void __exit drv_exit(void)
{
    device_destroy(dev_class, MKDEV(major, 0));
    class_destroy(dev_class);
    unregister_chrdev(major, DRV_NAME);
    drv_crypto_exit();
    pr_info(DRV_NAME ": Module unloaded\n");
}

module_init(drv_init);
module_exit(drv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fedor Kazakov");
MODULE_DESCRIPTION("Otus project (crypto_drv)");
MODULE_VERSION("1.0");

