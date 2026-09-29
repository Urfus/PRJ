#ifndef CRYPTO_H
#define CRYPTO_H

#include <linux/types.h>

#include "../inc/crypt_drv.h"

// инициализация крипто-контекста с указанием используемого алгоритма  
struct crypto_ctx* drv_crypto_init(enum my_crypto_type alg);
// реинициализация крипто-контекста со значениями установленными в структуре crypto_ctx 
int drv_crypto_reinit(struct crypto_ctx* ptr_crypto_ctx);

// закрытие крипто-контекста
void drv_crypto_exit(struct crypto_ctx* ptr_crypto_ctx);
// чтение используемого размера блока
size_t drv_crypto_blocksize(struct crypto_ctx* ptr_crypto_ctx);
// чтение размера используемого вектора инициализации
size_t drv_crypto_ivsize(struct crypto_ctx* ptr_crypto_ctx);

// зашифровать/расшивровать строку указанной длинны
int drv_do_crypto(struct crypto_ctx* ptr_crypto_ctx, char *buf, size_t len, int encrypt, u8 *iv);
// выровнять строку по размеру блока шифрования
size_t add_pkcs7_padding(char *buf, size_t len, size_t capacity, size_t block_size);
// удалить байты выравнования из расшифрованной строки
size_t remove_pkcs7_padding(char *buf, size_t len);

#endif // CRYPTO_H