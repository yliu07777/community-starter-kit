#ifndef __Q_PRIV_H__
#define __Q_PRIV_H__
#include <sys/queue.h>

#define STAILQ_FOREACH_SAFE(var, head, field, tvar)                     \
    for ((var) = STAILQ_FIRST((head));                                  \
         (var) && ((tvar) = STAILQ_NEXT((var), field), 1);              \
         (var) = (tvar))

#endif
