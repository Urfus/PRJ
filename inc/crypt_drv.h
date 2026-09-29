#ifndef CRYPT_DRV_H
#define CRYPT_DRV_H

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mutex.h>

#include "../inc/queue.h"
#include "../inc/crypt_api.h"

#define DRV_NAME "crypt_drv"

#define MAX_IV_SIZE 32

// Крипто-контекст, который определяет параметры алгоримта шифрования для потока
struct crypto_ctx {
    // Дескриптор преобразования для доступа к api ядра  
    struct crypto_skcipher *tfm;

    // вектор инициализации IV 
    u8 iv[MAX_IV_SIZE];
    // размер вектора (0 для ECB)         
    size_t ivsize;

    // выбранный алгоритм шифрования для потока
    enum my_crypto_type crypto_alg;
    // ключ шифрования
    char key_str[DRV_MAX_KEY_LEN];
};


// контекст потока
struct proc_ctx {
    // буфер потока
    struct ring_buffer *rb;
    // мютекс для конкурентного доступа к потоку
    struct mutex lock;
    // режим работы (ширование\дешифрование)
    int mode;

    // кропто-контекст 
    struct crypto_ctx *crypto_data;
};

// максимальная длина входной\выходной строки 
extern int max_length;
// extern char *default_key_str;

#endif // CRYPT_DRV_H