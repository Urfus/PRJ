#ifndef CRYPTO_H
#define CRYPTO_H

#include <linux/types.h>

int drv_crypto_init(void);
void drv_crypto_exit(void);
size_t drv_crypto_blocksize(void);
size_t drv_crypto_ivsize(void);
int drv_do_crypto(char *buf, size_t len, int encrypt, u8 *iv, size_t ivsize);
size_t add_pkcs7_padding(char *buf, size_t len, size_t capacity, size_t block_size);
size_t remove_pkcs7_padding(char *buf, size_t len);

#endif // CRYPTO_H