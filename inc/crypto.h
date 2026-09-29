#ifndef CRYPTO_H
#define CRYPTO_H

#include <linux/types.h>

#include "../inc/crypt_drv.h"


struct crypto_ctx* drv_crypto_init(enum my_crypto_type alg);
int drv_crypto_reinit(struct crypto_ctx* ptr_crypto_ctx);

void drv_crypto_exit(struct crypto_ctx* ptr_crypto_ctx);
size_t drv_crypto_blocksize(struct crypto_ctx* ptr_crypto_ctx);
size_t drv_crypto_ivsize(struct crypto_ctx* ptr_crypto_ctx);

int drv_do_crypto(struct crypto_ctx* ptr_crypto_ctx, char *buf, size_t len, int encrypt, u8 *iv);
size_t add_pkcs7_padding(char *buf, size_t len, size_t capacity, size_t block_size);
size_t remove_pkcs7_padding(char *buf, size_t len);

#endif // CRYPTO_H