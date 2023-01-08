#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

#define CONSOLE_OUTPUT 1
#define ERROR_STATUS -1

static void syscall_handler(struct intr_frame *);
static void syscall_exit(int status);
static tid_t syscall_exec(const char *cmd_args);
static int syscall_write(int fd, const void *buffer, unsigned size);

void validate_ptr(const void *_ptr);
void validate_str(const char *_str);
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
    char *cmd_args = *(char **)get_kth_ptr(f->esp, 1);
    validate_str(cmd_args);
    f->eax = syscall_exec(cmd_args);
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
    void *buffer = (void *)*get_kth_ptr(f->esp, 2);
    unsigned size = *((unsigned *)get_kth_ptr(f->esp, 3));

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

tid_t syscall_exec(const char *cmd_args)
{
  struct thread *curr_t = thread_current();
  struct thread *child_t;
  struct list_elem *child_elem;

  // execute cmd_args and make a child process
  // printf("## from %s sys exec %s \n", thread_current()->name, cmd_args);
  tid_t child_tid = process_execute(cmd_args);
  if (child_tid == TID_ERROR)
  {
    return child_tid;
  }

  // Check if child_tid is in current threads children.
  for (
      child_elem = list_begin(&curr_t->child_list);
      child_elem != list_end(&curr_t->child_list);
      child_elem = list_next(child_elem))
  {
    child_t = list_entry(child_elem, struct thread, child_elem);
    if (child_t->tid == child_tid)
    {
      break;
    }
  }
  // If child with child_tid was not in list, its not a child of the calling process
  if (child_elem == list_end(&curr_t->child_list))
  {
    return ERROR_STATUS;
  }

  // printf("# %s wait for child %s init \n", curr_t->name, child_t->name);
  sema_down(&child_t->init_sema);
  if (!child_t->status_load_success)
  {
    return ERROR_STATUS;
  }

  return child_tid;
}

void validate_ptr(const void *_ptr)
{
  struct thread *curr_t;
  curr_t = thread_current();

  if (_ptr == NULL)
  {
    // obviusly shouldnt be a null pointer
    syscall_exit(ERROR_STATUS);
  }
  if (is_kernel_vaddr(_ptr))
  {
    // shouldn't be in kernel address space
    // NOTE: this should be called before pagedir_get_page to prevent an assertion error
    syscall_exit(ERROR_STATUS);
  }
  if (pagedir_get_page(curr_t->pagedir, _ptr) == NULL)
  {
    // address should be mapped
    syscall_exit(ERROR_STATUS);
  }
}

void validate_str(const char *_str)
{
  validate_ptr((void *)_str);
  for (
      int k = 0;
      *((char *)_str + k) != 0;
      k++)
  {
    validate_ptr((void *)((char *)_str + k + 1));
  }
}

int *get_kth_ptr(const void *_ptr, int _k)
{
  int *next_ptr = (int *)_ptr + _k;
  validate_ptr((void *)next_ptr);
  // Catch the edge case where just a part of the value is in valid address space
  validate_ptr((void *)(next_ptr + 1));
  return next_ptr;
}