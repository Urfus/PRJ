#include <linux/slab.h>
#include <linux/string.h>

#include "../inc/queue.h"

struct ring_buffer *rb_init(size_t capacity)
{
    struct ring_buffer *rb;

    rb = kzalloc(sizeof(*rb), GFP_KERNEL);
    if (!rb)
        return NULL;

    rb->data = kmalloc(capacity, GFP_KERNEL);
    if (!rb->data) {
        kfree(rb);
        return NULL;
    }

    rb->capacity = capacity;
    spin_lock_init(&rb->lock);
    return rb;
}

void rb_free(struct ring_buffer *rb)
{
    if (!rb)
        return;
    kfree(rb->data);
    kfree(rb);
}

size_t rb_put(struct ring_buffer *rb, const char *buf, size_t len)
{
    unsigned long flags;
    size_t to_write, first, second;

    spin_lock_irqsave(&rb->lock, flags);

    to_write = min(len, rb->capacity - rb->count);
    if (!to_write) {
        spin_unlock_irqrestore(&rb->lock, flags);
        return 0;
    }

    first  = min(to_write, rb->capacity - rb->tail);
    second = to_write - first;

    memcpy(rb->data + rb->tail, buf, first);
    if (second)
        memcpy(rb->data, buf + first, second);

    rb->tail = (rb->tail + to_write) % rb->capacity;
    rb->count += to_write;

    spin_unlock_irqrestore(&rb->lock, flags);
    return to_write;
}

size_t rb_get(struct ring_buffer *rb, char *buf, size_t len)
{
    unsigned long flags;
    size_t to_read, first, second;

    spin_lock_irqsave(&rb->lock, flags);

    to_read = min(len, rb->count);
    if (!to_read) {
        spin_unlock_irqrestore(&rb->lock, flags);
        return 0;
    }

    first  = min(to_read, rb->capacity - rb->head);
    second = to_read - first;

    memcpy(buf, rb->data + rb->head, first);
    if (second)
        memcpy(buf + first, rb->data, second);

    rb->head = (rb->head + to_read) % rb->capacity;
    rb->count -= to_read;

    spin_unlock_irqrestore(&rb->lock, flags);
    return to_read;
}

void rb_flush(struct ring_buffer *rb)
{
    unsigned long flags;

    spin_lock_irqsave(&rb->lock, flags);
    rb->head  = 0;
    rb->tail  = 0;
    rb->count = 0;
    spin_unlock_irqrestore(&rb->lock, flags);
}