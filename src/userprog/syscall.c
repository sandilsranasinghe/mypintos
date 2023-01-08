#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

#define CONSOLE_OUTPUT 1
#define SYS_EXIT_STATUS_ERROR -1

static void syscall_handler(struct intr_frame *);
static void syscall_exit(int status);
static int syscall_write(int fd, const void *buffer, unsigned size);

void validate_ptr(const void *_ptr);
int *get_kth_ptr(const void *_ptr, int _k);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  validate_ptr(f->esp);
  int syscall_type = *get_kth_ptr(f->esp, 0);
  // printf("syscall %d \n", syscall_type);

  switch (syscall_type)
  {
  case SYS_HALT:
  {
    shutdown_power_off();
    break;
  }

  case SYS_EXIT:
  {
    // get args
    int status = *get_kth_ptr(f->esp, 1);
    syscall_exit(status);
    break;
  }

  case SYS_EXEC:
  {
    break;
  }

  case SYS_WAIT:
  {
    break;
  }

  case SYS_CREATE:
  {
    break;
  }

  case SYS_REMOVE:
  {
    break;
  }

  case SYS_OPEN:
  {
    break;
  }

  case SYS_FILESIZE:
  {
    break;
  }

  case SYS_READ:
  {
    break;
  }

  case SYS_WRITE:
  {
    // get args
    int fd = *get_kth_ptr(f->esp, 1);
    void *buffer = (void *) *get_kth_ptr(f->esp, 2);
    unsigned size = *((unsigned *) get_kth_ptr(f->esp, 3));

    f->eax = syscall_write(fd, buffer, size);
    break;
  }

  case SYS_SEEK:
  {
    break;
  }

  case SYS_TELL:
  {
    break;
  }

  case SYS_CLOSE:
  {
    break;
  }

  default:
  {
    // TODO?
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

void validate_ptr(const void *_ptr)
{
  struct thread *curr_t;
  curr_t = thread_current();

  if (_ptr == NULL) {
    // obviusly shouldnt be a null pointer
    syscall_exit(SYS_EXIT_STATUS_ERROR);
  }
  if (is_kernel_vaddr(_ptr)) {
    // shouldn't be in kernel address space
    // NOTE: this should be called before pagedir_get_page to prevent an assertion error
    syscall_exit(SYS_EXIT_STATUS_ERROR);
  }
  if (pagedir_get_page(curr_t->pagedir, _ptr) == NULL) {
    // address should be mapped
    syscall_exit(SYS_EXIT_STATUS_ERROR);
  }
}

int *get_kth_ptr(const void *_ptr, int _k)
{
  int *next_ptr = (int*) _ptr + _k;
  validate_ptr((void *) next_ptr);
  validate_ptr((void *) (next_ptr+1));
  return next_ptr;
}