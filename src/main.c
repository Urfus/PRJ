#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#include "../inc/crypt_drv.h"
#include "../inc/params.h"

int max_length = 4096;

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

    mutex_init(&ctx->lock);
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
    size_t written;

    if (!count)
        return 0;

    kbuf = memdup_user(ubuf, count);
    if (IS_ERR(kbuf))
        return PTR_ERR(kbuf);

    mutex_lock(&ctx->lock);
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
    drv_params_init();

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
    return 0;
}

static void __exit drv_exit(void)
{
    device_destroy(dev_class, MKDEV(major, 0));
    class_destroy(dev_class);
    unregister_chrdev(major, DRV_NAME);
    drv_params_exit();
    pr_info(DRV_NAME ": Module unloaded\n");
}

module_init(drv_init);
module_exit(drv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fedor Kazakov");
MODULE_DESCRIPTION("Otus project (crypto_drv)");
MODULE_VERSION("1.0");

