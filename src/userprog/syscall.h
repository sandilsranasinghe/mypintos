#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

struct lock file_system_lock;       // lock for accessing file system

void syscall_init (void);

#endif /* userprog/syscall.h */
