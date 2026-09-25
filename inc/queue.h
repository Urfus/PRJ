#ifndef QUEUE_H
#define QUEUE_H

#include <linux/types.h>
#include <linux/spinlock.h>

struct ring_buffer {
    char *data;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    spinlock_t lock;
};

struct ring_buffer *rb_init(size_t capacity);
void rb_free(struct ring_buffer *rb);
size_t rb_put(struct ring_buffer *rb, const char *buf, size_t len);
size_t rb_get(struct ring_buffer *rb, char *buf, size_t len);
void rb_flush(struct ring_buffer *rb);

#endif // QUEUE_H 