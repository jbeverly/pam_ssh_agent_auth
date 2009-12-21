#ifndef _IDENTITY_H
#define _IDENTITY_H
#include "includes.h"
#include "config.h"

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "authfd.h"
#include <stdio.h>

typedef struct identity Identity;
typedef struct idlist Idlist;

struct identity {
    TAILQ_ENTRY(identity) next;
    AuthenticationConnection *ac;   /* set if agent supports key */
    Key *key;           /* public/private key */
    char    *filename;      /* comment for agent-only keys */
    int tried;
    int isprivate;      /* key points to the private key */
};
TAILQ_HEAD(idlist, identity);
#endif
