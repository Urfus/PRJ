#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

// #define IOCTL_SET_MODE _IOW('D', 1, int)
// #define MODE_ENCRYPT 0
// #define MODE_DECRYPT 1

int main() {
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    char plain[] = "Hello, Kernel Crypto!";
    char buf_out[64] = {0};
    int mode;

    // // 1. Режим шифрования
    // mode = MODE_ENCRYPT;
    // ioctl(fd, IOCTL_SET_MODE, &mode);

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов
    
    ssize_t rl = read(fd, buf_out, sizeof(buf_out));
    printf("Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов

    buf_out[0] = 0;
    rl = read(fd, buf_out, sizeof(buf_out));
    printf("Повторное чтение - Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов


    wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов
    wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов

    rl = read(fd, buf_out, sizeof(buf_out));
    printf("Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов


    // // 2. Режим дешифрования (пишем то, что прочитали, читаем оригинал)
    // mode = MODE_DECRYPT;
    // ioctl(fd, IOCTL_SET_MODE, &mode);
    // write(fd, buf_out, strlen(plain)); // Пишем шифротекст
    
    // memset(buf_out, 0, sizeof(buf_out));
    // read(fd, buf_out, sizeof(buf_out));
    // printf("Decrypted read: %s\n", buf_out); // Вернется "Hello, Kernel Crypto!"

    close(fd);
    return 0;
}