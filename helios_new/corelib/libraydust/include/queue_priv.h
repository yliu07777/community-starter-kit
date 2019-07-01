#ifndef _QUEUE_PRIV_H_
#define _QUEUE_PRIV_H_
#include <sys/queue.h>


#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                     \
    for ((var) = STAILQ_FIRST((head));                                  \
         (var) && ((tvar) = STAILQ_NEXT((var), field), 1);              \
         (var) = (tvar))

#define	STAILQ_LAST(head, type, field)					\
	(STAILQ_EMPTY(head) ?						\
		NULL :							\
	        ((struct type *)					\
		((char *)((head)->stqh_last) - offsetof(struct type, field))))

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                     \
    for ((var) = TAILQ_FIRST((head));                                  \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1);              \
         (var) = (tvar))

#define LIST_FOREACH_SAFE(var, head, field, tvar)                       \
    for ((var) = LIST_FIRST((head));                                    \
         (var) && ((tvar) = LIST_NEXT((var), field), 1);                \
         (var) = (tvar))

#define CIRCLEQ_FOREACH_SAFE(var, head, field, tvar)                    \
        for ((var) = CIRCLEQ_FIRST((head));                             \
            ((var) != (void *)(head) || ((var) = NULL)) &&              \
            ((tvar) = CIRCLEQ_NEXT((var), field));                      \
            (var) = (tvar))

/* Packet queue. */
struct ofp_queue {
    int n;                      /* Number of queued packets. */
    struct ofpbuf *head;        /* First queued packet, null if n == 0. */
    struct ofpbuf *tail;        /* Last queued packet, null if n == 0. */
};

void queue_init(struct ofp_queue *);
void queue_destroy(struct ofp_queue *);
int  queue_iter(struct ofp_queue *, int select, void *arg, int (*iter)(struct ofpbuf *, int, void *));
void queue_clear(struct ofp_queue *);
void queue_advance_head(struct ofp_queue *, struct ofpbuf *next);
void queue_push_tail(struct ofp_queue *, struct ofpbuf *);
struct ofpbuf *queue_pop_head(struct ofp_queue *);


#endif
