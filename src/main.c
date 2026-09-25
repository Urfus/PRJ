#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/slab.h>

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DRV_NAME "crypt_drv"

static int major;
static struct class *dev_class;
static struct device *dev;

static int drv_open(struct inode *inode, struct file *file)
{
    pr_info(DRV_NAME ": Device opened by PID %d\n", current->pid);
    return 0;
}

static int drv_release(struct inode *inode, struct file *file)
{
    pr_info(DRV_NAME ": Device closed by PID %d\n", current->pid);
    return 0;
}

static const struct file_operations drv_fops = {
    .owner   = THIS_MODULE,
    .open    = drv_open,
    .release = drv_release,
};

static int __init drv_init(void)
{
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

    /* 3. Создание узла /dev/cript_drv */
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
    pr_info(DRV_NAME ": Module unloaded\n");
}

module_init(drv_init);
module_exit(drv_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fedor Kazakov");
MODULE_DESCRIPTION("Otus project (crypto_drv)");
MODULE_VERSION("1.0");

