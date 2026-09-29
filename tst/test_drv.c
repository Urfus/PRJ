#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "../inc/crypt_api.h"

static int test_1(void);
static int test_2(void);
static int test_3(void);
static int test_4(void);
static int test_5(void);
static int test_6(void);
static int test_7(void);
static int test_8(void);

struct test_case {
    const char *name; 
    int (*func)(void);  
};

static const struct test_case tests[] = {
    {"Basic open/close",                                        test_1 },
    {"Write and read",                                          test_2 },
    {"Encryption mode (default algo and key string)",           test_3 },
    {"Encryption mode (algo CBC AES)",                          test_4 },
    {"Encryption mode (algo ECB AES)",                          test_5 },
    {"Key string change",                                       test_6 },
    {"Multy threads mode with default value",                   test_7 },
    {"Multy threads mode with different value",                 test_8 },
};

#define NUM_TESTS (sizeof(tests) / sizeof(tests[0]))

static pthread_barrier_t sync_barrier;

static int run_test(int test_num)
{
    int ret;

    if ( (test_num < 0) || (test_num > (int)NUM_TESTS) )
        return -1;

    printf("\n========================================\n");
    printf("Running test %d: %s\n", test_num+1, tests[test_num].name);
    printf("========================================\n");
    
    ret = tests[test_num].func();
    
    if (ret == 0) {
        printf("✓ Test %d PASSED\n", test_num+1);
    } else {
        printf("✗ Test %d FAILED (error code: %d)\n", test_num+1, ret);
    }
            
    return ret;
}

static int run_all_tests(void)
{
    int i;
    int ret;
    int failed = 0;
    int passed = 0;

    printf("\n========================================\n");
    printf("Running ALL tests (%zu total)\n", NUM_TESTS);
    printf("========================================\n");

    for (i = 1; i <= (int)NUM_TESTS; i++) {
        ret = run_test(i - 1);
        if (ret == 0) {
            passed++;
        } else {
            failed++;
        }
    }

    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total:  %zu\n", NUM_TESTS);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    printf("========================================\n");

    return (failed > 0) ? 1 : 0;
}

static int test_1(void)
{
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    if (close(fd) != 0) {
        perror("close /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };
    
    return 0; 
}

static int test_2(void)
{
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    char plain[] = "** test string **";
    char buf_out[64] = {0};

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка (исходная): %s\n", wl, plain); 
    if (wl < 0) {
        perror("write /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    ssize_t rl = read(fd, buf_out, sizeof(buf_out));
    printf("Прочитано байт: %lu, строка (зашифрованая): %s\n", rl, buf_out); 
    if (rl < 0) {
        perror("read /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    if (close(fd) != 0) {
        perror("close /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    return 0;
}

static int test_3(void)
{
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    char plain[] = "** test string **";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};

    enum my_crypto_mode mode = MODE_ENCRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_ENCRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка (исходная): %s\n", wl, plain); 
    if (wl < 0) {
        perror("write (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("Прочитано байт: %lu, строка (зашифрованая): %s\n", rl, buf_out_enc); 
    if (rl < 0) {
        perror("read (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    mode = MODE_DECRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_DECRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    wl = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("Записано байт: %lu, строка (зашифрованная): %s\n", wl, buf_out_enc); 
    if (wl < 0) {
        perror("write (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    rl = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("Прочитано байт: %lu, строка (расшифрованая): %s\n", rl, buf_out_dec);
    if (rl < 0) {
        perror("read (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    if (strcmp(buf_out_dec, plain) != 0) {
        printf("Строки не совпадают, Исходная: %s, Полученная: %s", plain, buf_out_dec); 
        return EXIT_FAILURE;   
    }


    if (close(fd) != 0) {
        perror("close /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    return 0;
}

static int test_4(void)
{
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    char plain[] = "** test string **";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};

    enum my_crypto_type algo = ALGO_CBC_AES;
    if (ioctl(fd, IOCTL_SET_CRYPTO_ALG, &algo) < 0) {
        perror("ioctl CRYPTO_ALG /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    enum my_crypto_mode mode = MODE_ENCRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_ENCRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка (исходная): %s\n", wl, plain); 
    if (wl < 0) {
        perror("write (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("Прочитано байт: %lu, строка (зашифрованая): %s\n", rl, buf_out_enc); 
    if (rl < 0) {
        perror("read (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    mode = MODE_DECRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_DECRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    wl = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("Записано байт: %lu, строка (зашифрованная): %s\n", wl, buf_out_enc); 
    if (wl < 0) {
        perror("write (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    rl = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("Прочитано байт: %lu, строка (расшифрованая): %s\n", rl, buf_out_dec);
    if (rl < 0) {
        perror("read (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    if (strcmp(buf_out_dec, plain) != 0) {
        printf("Строки не совпадают, Исходная: %s, Полученная: %s", plain, buf_out_dec); 
        return EXIT_FAILURE;   
    }


    if (close(fd) != 0) {
        perror("close /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    return 0;
}

static int test_5(void)
{
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    char plain[] = "** test string **";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};

    enum my_crypto_type algo = ALGO_ECB_AES;
    if (ioctl(fd, IOCTL_SET_CRYPTO_ALG, &algo) < 0) {
        perror("ioctl CRYPTO_ALG /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    enum my_crypto_mode mode = MODE_ENCRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_ENCRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка (исходная): %s\n", wl, plain); 
    if (wl < 0) {
        perror("write (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("Прочитано байт: %lu, строка (зашифрованая): %s\n", rl, buf_out_enc); 
    if (rl < 0) {
        perror("read (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    mode = MODE_DECRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_DECRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    wl = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("Записано байт: %lu, строка (зашифрованная): %s\n", wl, buf_out_enc); 
    if (wl < 0) {
        perror("write (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    rl = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("Прочитано байт: %lu, строка (расшифрованая): %s\n", rl, buf_out_dec);
    if (rl < 0) {
        perror("read (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    if (strcmp(buf_out_dec, plain) != 0) {
        printf("Строки не совпадают, Исходная: %s, Полученная: %s", plain, buf_out_dec); 
        return EXIT_FAILURE;   
    }


    if (close(fd) != 0) {
        perror("close /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    return 0;
}

static int test_6(void)
{
    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    char plain[] = "** test string **";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};

    // enum my_crypto_type algo = ALGO_ECB_AES;
    // if (ioctl(fd, IOCTL_SET_CRYPTO_ALG, &algo) < 0) {
    //     perror("ioctl CRYPTO_ALG /dev/crypt_drv"); 
    //     return EXIT_FAILURE; 
    // };

    struct drv_key_param new_key = {"abcdefghabcdefgh", sizeof("abcdefghabcdefgh")}; 
 
    if (ioctl(fd, IOCTL_SET_KEY_STR, &new_key) < 0) {
        perror("ioctl SET_KEY_STR /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    enum my_crypto_mode mode = MODE_ENCRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_ENCRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("Записано байт: %lu, строка (исходная): %s\n", wl, plain); 
    if (wl < 0) {
        perror("write (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("Прочитано байт: %lu, строка (зашифрованая): %s\n", rl, buf_out_enc); 
    if (rl < 0) {
        perror("read (step 1) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    mode = MODE_DECRYPT;
    if (ioctl(fd, IOCTL_SET_MODE, &mode) < 0) {
        perror("ioctl MODE_DECRYPT /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    wl = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("Записано байт: %lu, строка (зашифрованная): %s\n", wl, buf_out_enc); 
    if (wl < 0) {
        perror("write (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    rl = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("Прочитано байт: %lu, строка (расшифрованая): %s\n", rl, buf_out_dec);
    if (rl < 0) {
        perror("read (step 2) /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    }

    if (strcmp(buf_out_dec, plain) != 0) {
        printf("Строки не совпадают, Исходная: %s, Полученная: %s", plain, buf_out_dec); 
        return EXIT_FAILURE;   
    }


    if (close(fd) != 0) {
        perror("close /dev/crypt_drv"); 
        return EXIT_FAILURE; 
    };

    return 0;
}
void* test_7_thread(void* arg) {

    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) { perror("open"); return NULL; }

    char plain[] = "second test string";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};
    int mode;

    mode = MODE_ENCRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    pthread_barrier_wait(&sync_barrier);

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("second: Записано байт: %lu, строка: %s\n", wl, plain); 

    pthread_barrier_wait(&sync_barrier);
    
    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("second: Прочитано байт (зашифровано): %lu, строка: %s\n", rl, buf_out_enc); 

    mode = MODE_DECRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    ssize_t w2 = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("second: Записано байт: %lu, строка: %s\n", w2, buf_out_enc); 

    pthread_barrier_wait(&sync_barrier);

    ssize_t r2 = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("second: Прочитано байт (расшифровано): %lu, строка: %s\n", r2, buf_out_dec); // Будет набор нечитаемых символов

    close(fd);
    printf("second: Stop thread\n");

    return NULL;
}


static int test_7(void)
{
    pthread_t pth_second;

    if (pthread_barrier_init(&sync_barrier, NULL, 2) != 0) {
        perror("error init barrier");
        return EXIT_FAILURE;
    }

    if (pthread_create(&pth_second, NULL, test_7_thread, NULL) != 0) {
        perror("Error pthread_create");
        return EXIT_FAILURE;
    }

    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    char plain[] = "first test string";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};
    int mode;

    mode = MODE_ENCRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    pthread_barrier_wait(&sync_barrier);

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("first: Записано байт: %lu, строка: %s\n", wl, plain); 

    pthread_barrier_wait(&sync_barrier);

    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("first: Прочитано байт (зашифровано): %lu, строка: %s\n", rl, buf_out_enc); 

    mode = MODE_DECRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    ssize_t w2 = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("first: Записано байт: %lu, строка: %s\n", w2, buf_out_enc); 

    pthread_barrier_wait(&sync_barrier);

    ssize_t r2 = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("first: Прочитано байт (расшифровано): %lu, строка: %s\n", r2, buf_out_dec); // Будет набор нечитаемых символов

    close(fd);
    printf("first: Stop thread\n");

    if (pthread_join(pth_second, NULL) != 0) {
        perror("Error pthread_join");
        return EXIT_FAILURE;
    }

    pthread_barrier_destroy(&sync_barrier);

    return 0;
}

static int test_8(void)
{
    pthread_t pth_second;

    if (pthread_barrier_init(&sync_barrier, NULL, 2) != 0) {
        perror("error init barrier");
        return EXIT_FAILURE;
    }

    if (pthread_create(&pth_second, NULL, test_7_thread, NULL) != 0) {
        perror("Error pthread_create");
        return EXIT_FAILURE;
    }

    int fd = open("/dev/crypt_drv", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    char plain[] = "first test string";
    char buf_out_enc[64] = {0};
    char buf_out_dec[64] = {0};
    int mode;

    enum my_crypto_type algo = ALGO_CBC_AES;
    ioctl(fd, IOCTL_SET_CRYPTO_ALG, &algo);
        
    mode = MODE_ENCRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    struct drv_key_param new_key = {"abcdefghabcdefgh", sizeof("abcdefghabcdefgh")}; 
    ioctl(fd, IOCTL_SET_KEY_STR, &new_key);


    pthread_barrier_wait(&sync_barrier);

    ssize_t wl = write(fd, plain, strlen(plain));
    printf("first: Записано байт: %lu, строка: %s\n", wl, plain); 

    pthread_barrier_wait(&sync_barrier);

    ssize_t rl = read(fd, buf_out_enc, sizeof(buf_out_enc));
    printf("first: Прочитано байт (зашифровано): %lu, строка: %s\n", rl, buf_out_enc); 

    mode = MODE_DECRYPT;
    ioctl(fd, IOCTL_SET_MODE, &mode);

    ssize_t w2 = write(fd, buf_out_enc, strlen(buf_out_enc));
    printf("first: Записано байт: %lu, строка: %s\n", w2, buf_out_enc); 

    pthread_barrier_wait(&sync_barrier);

    ssize_t r2 = read(fd, buf_out_dec, sizeof(buf_out_dec));
    printf("first: Прочитано байт (расшифровано): %lu, строка: %s\n", r2, buf_out_dec); // Будет набор нечитаемых символов

    close(fd);
    printf("first: Stop thread\n");

    if (pthread_join(pth_second, NULL) != 0) {
        perror("Error pthread_join");
        return EXIT_FAILURE;
    }

    pthread_barrier_destroy(&sync_barrier);

    return 0;
}

int main(int argc, char *argv[])
{
    int test_num = 0;
    char *endptr;

    // Разбор аргументов командной строки
    if (argc > 1) {

        // Преобразование строки в число
        errno = 0;
        test_num = strtol(argv[1], &endptr, 10);

        // Проверка на ошибки преобразования
        if (errno != 0) {
            fprintf(stderr, "Error: Invalid number '%s': %s\n", 
                    argv[1], strerror(errno));
            return 1;
        }

        // Проверка, что вся строка была числом
        if (*endptr != '\0') {
            fprintf(stderr, "Error: Invalid number '%s' (trailing characters)\n", 
                    argv[1]);
            return 1;
        }

        if ( (test_num < 0) || (test_num > (int)NUM_TESTS) ) {
            fprintf(stderr, "Error: Invalid test number '%s' \n", 
                    argv[1]);
            return 1;
        }
    }


    // Выполнение тестов
    if (test_num == 0) {
        // Запуск всех тестов
        return run_all_tests();
    } else {
        // Запуск конкретного теста
        return run_test(test_num - 1);
    }
}
