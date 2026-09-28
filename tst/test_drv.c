#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define IOCTL_SET_MODE _IOW('D', 1, int)
#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

pthread_barrier_t sync_barrier;

void* second_thread(void* arg) {
    printf("SECOND: start thread\n");

    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) { perror("open"); return NULL; }

    printf("SECOND: open device - OK\n");

    char plain[] = "SECOND: Hello !!";
    char buf_out[64] = {0};
    char buf_ctrl[64] = {0};
    int mode;

    mode = MODE_ENCRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    pthread_barrier_wait(&sync_barrier); 

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("SECOND: Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов
    
    ssize_t rl = read(fd, buf_out, sizeof(buf_out));
    printf("SECOND: Прочитано байт (зашифровано): %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов

    mode = MODE_DECRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    ssize_t w2 = write(fd, buf_out, strlen(buf_out));
    printf("SECOND: Записано байт: %lu, строка: %s\n", w2, buf_out); // Будет набор нечитаемых символов

    ssize_t r2 = read(fd, buf_ctrl, sizeof(buf_ctrl));
    printf("SECOND: Прочитано байт (расшифровано): %lu, строка: %s\n", r2, buf_ctrl); // Будет набор нечитаемых символов

    pthread_barrier_wait(&sync_barrier); 

    buf_out[0] = 0;
    rl = read(fd, buf_out, sizeof(buf_out));
    printf("SECOND: Повторное чтение - Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов


    wl = write(fd, plain, strlen(plain));
    printf("SECOND: Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов
    wl = write(fd, plain, strlen(plain));
    printf("SECOND: Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов

    pthread_barrier_wait(&sync_barrier); 

    rl = read(fd, buf_out, sizeof(buf_out));
    printf("SECOND: Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов


    close(fd);
    printf("SECOND: Stop thread\n");

    return NULL;
}


int main() {
    printf("Start test modules\n");

    pthread_t pth_second;

    if (pthread_barrier_init(&sync_barrier, NULL, 2) != 0) {
        perror("error init barrier");
        return EXIT_FAILURE;
    }

    if (pthread_create(&pth_second, NULL, second_thread, NULL) != 0) {
        perror("Error pthread_create");
        return EXIT_FAILURE;
    }

    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    printf("FIRST: open device - OK\n");

    char plain[] = "FIRST: Hello !!";
    char buf_out[64] = {0};
    int mode;

    // // 1. Режим шифрования
    // mode = MODE_ENCRYPT;
    // ioctl(fd, IOCTL_SET_MODE, &mode);

    pthread_barrier_wait(&sync_barrier); 

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("FIRST: Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов
    
    ssize_t rl = read(fd, buf_out, sizeof(buf_out));
    printf("FIRST: Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов

    pthread_barrier_wait(&sync_barrier); 

    buf_out[0] = 0;
    rl = read(fd, buf_out, sizeof(buf_out));
    printf("FIRST: Повторное чтение - Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов


    wl = write(fd, plain, strlen(plain));
    printf("FIRST: Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов
    wl = write(fd, plain, strlen(plain));
    printf("FIRST: Записано байт: %lu, строка: %s\n", wl, plain); // Будет набор нечитаемых символов

    pthread_barrier_wait(&sync_barrier); 

    rl = read(fd, buf_out, sizeof(buf_out));
    printf("FIRST: Прочитано байт: %lu, строка: %s\n", rl, buf_out); // Будет набор нечитаемых символов

    if (pthread_join(pth_second, NULL) != 0) {
        perror("Error pthread_join");
        return EXIT_FAILURE;
    }

    pthread_barrier_destroy(&sync_barrier);

    close(fd);
    printf("Stop test modules\n");
    return 0;
}