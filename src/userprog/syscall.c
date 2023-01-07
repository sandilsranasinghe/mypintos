#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define CONSOLE_OUTPUT 1

static void syscall_handler(struct intr_frame *);
static void syscall_exit(int status);
static int syscall_write(int fd, const void *buffer, unsigned size);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // TODO check valid esp

  int syscall_type = *(int *)f->esp;
  // printf("syscall %d \n", syscall_type);

  switch (syscall_type)
  {
  case SYS_EXIT:
  {
    int status = *(((int *)f->esp) + 1);
    syscall_exit(status);
    break;
  }

  case SYS_WRITE:
  {
    // get args
    int fd = *((int *)f->esp + 1);
    void *buffer = (void *)(*((int *)f->esp + 2));
    unsigned size = *((unsigned *)f->esp + 3);

    f->eax = syscall_write(fd, buffer, size);
    break;
  }

  default:
  {
    break;
  }
  }
}

static void syscall_exit(int status)
{
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

static int syscall_write(int fd, const void *buffer, unsigned size)
{
  char *_buffer = (char *)buffer;
  int written_size = 0;

  if (fd == CONSOLE_OUTPUT)
  {
    putbuf(_buffer, size);
    written_size = size;
  }
  else
  {
    // TODO write to files
  }

  return written_size;
}
