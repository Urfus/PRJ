#ifndef QUEUE_H
#define QUEUE_H

#include <linux/types.h>
#include <linux/spinlock.h>

// кольцевой буфер для хранения вводимой информации
struct ring_buffer {
    char *data;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    spinlock_t lock;
};

// Инициализация буфера
struct ring_buffer *rb_init(size_t capacity);
// удаление буфера
void rb_free(struct ring_buffer *rb);
// запись в буфер произвольного числа байт
size_t rb_put(struct ring_buffer *rb, const char *buf, size_t len);
// чтение из буфера произвольного числа байт
size_t rb_get(struct ring_buffer *rb, char *buf, size_t len);
// очистка буфера
void rb_flush(struct ring_buffer *rb);

#endif // QUEUE_H 