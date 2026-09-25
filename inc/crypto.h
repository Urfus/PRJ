#ifndef CRYPTO_H
#define CRYPTO_H

#include <linux/types.h>

int drv_crypto_init(void);
void drv_crypto_exit(void);
int drv_do_crypto(char *buf, size_t len, int encrypt);

#endif // CRYPTO_H