#ifndef CRYPT_API_H
#define CRYPT_API_H

#define CMD_SET_MODE        1
#define CMD_SET_CRYPTO_ALG  2
#define CMD_SET_KEY_STR     3

#define IOCTL_SET_MODE          _IOW('D', CMD_SET_MODE, int)
#define IOCTL_SET_CRYPTO_ALG    _IOW('D', CMD_SET_CRYPTO_ALG, int)
#define IOCTL_SET_KEY_STR       _IOW('D', CMD_SET_KEY_STR, int)

#define DRV_MAX_KEY_LEN 64  // Максимальная длина ключа


enum my_crypto_type {
    ALGO_ECB_AES    = 0,
    ALGO_CBC_AES    = 1,
};

enum my_crypto_mode {
    MODE_ENCRYPT = 0,
    MODE_DECRYPT = 1
};

// Структура для передачи ключа
struct drv_key_param {
    char key_str[DRV_MAX_KEY_LEN];  // Буфер для ключа
    size_t key_len;             // Реальная длина ключа
};

#endif // CRYPT_API_H
