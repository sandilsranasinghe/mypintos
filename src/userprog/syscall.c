#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"

#define CONSOLE_OUTPUT 1
#define ERROR_STATUS -1

static void syscall_handler(struct intr_frame *);
static void syscall_exit(int status);
static tid_t syscall_exec(const char *cmd_args);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void *buffer, unsigned size);
static int syscall_write(int fd, const void *buffer, unsigned size);
static void syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static void syscall_close(int fd);

void validate_ptr(const void *_ptr);
void validate_str(const char *_str);
int *get_kth_ptr(const void *_ptr, int _k);
struct file_descriptor *get_from_fd(int fd);

void syscall_init(void)
{
  lock_init(&file_system_lock);
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
    char *file = *(char **)get_kth_ptr(f->esp, 1);
    validate_str(file);
    unsigned initial_size = *((unsigned *)get_kth_ptr(f->esp, 2));
    f->eax = syscall_create(file, initial_size);
    break;
  }

  case SYS_REMOVE:
  {
    char *file = *(char **)get_kth_ptr(f->esp, 1);
    validate_str(file);
    f->eax = syscall_remove(file);
    break;
  }

  case SYS_OPEN:
  {
    char *file = *(char **)get_kth_ptr(f->esp, 1);
    validate_str(file);
    f->eax = syscall_open(file);
    break;
  }

  case SYS_FILESIZE:
  {
    int fd = *get_kth_ptr(f->esp, 1);
    f->eax = syscall_filesize(fd);
    break;
  }

  case SYS_READ:
  {
    break;
  }

  case SYS_WRITE:
  {
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
    int fd = *get_kth_ptr(f->esp, 1);
    syscall_close(fd);
    break;
  }

  default:
  {
    // TODO what happens here?
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

static tid_t syscall_exec(const char *cmd_args)
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

static bool syscall_create(const char *file, unsigned initial_size)
{
  // acquire lock before accessing file system and release afterwards
  lock_acquire(&file_system_lock);
  bool create_status = filesys_create(file, initial_size);
  lock_release(&file_system_lock);

  return create_status;
}

static bool syscall_remove(const char *file)
{
  // acquire lock before accessing file system and release afterwards
  lock_acquire(&file_system_lock);
  bool remove_status = filesys_remove(file);
  lock_release(&file_system_lock);

  return remove_status;
}

static int syscall_open(const char *file)
{
  struct file_descriptor *_file_descriptor = malloc(sizeof(struct file_descriptor *));
  struct file *_file;
  struct thread *curr_t;

  // acquire lock before accessing file system and release afterwards
  lock_acquire((&file_system_lock));
  _file = filesys_open(file);
  lock_release(&file_system_lock);

  if (_file == NULL)
  {
    return ERROR_STATUS;
  }

  curr_t = thread_current();
  _file_descriptor->fd = curr_t->next_fd;
  curr_t->next_fd++; // Increment next fd so that it will be different for the next file opened by process
  _file_descriptor->_file = _file;
  list_push_back(&curr_t->open_fd_list, &_file_descriptor->fd_elem);

  return _file_descriptor->fd;
}

static int syscall_filesize(int fd)
{
  struct file_descriptor *_file_descriptor = get_from_fd(fd);
  int file_size;
  if (_file_descriptor == NULL)
  {
    return ERROR_STATUS;
  }

  lock_acquire((&file_system_lock));
  file_size = file_length(_file_descriptor->_file);
  lock_release(&file_system_lock);

  return file_size;
}

static void syscall_close(int fd)
{
  struct file_descriptor *_file_descriptor = get_from_fd(fd);
  int file_size;
  if (_file_descriptor != NULL)
  {
    lock_acquire((&file_system_lock));
    file_close(_file_descriptor->_file);
    lock_release(&file_system_lock);

    list_remove(&_file_descriptor->fd_elem);
  }
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

// Get a file_descriptor from the current process' list of open file descriptors using
// the given fd value
struct file_descriptor *get_from_fd(int fd)
{
  struct thread *curr_t = thread_current();
  struct file_descriptor *_file_descriptor;
  struct list_elem *fd_elem;

  // Check if child_tid is in current threads children.
  for (
      fd_elem = list_begin(&curr_t->open_fd_list);
      fd_elem != list_end(&curr_t->open_fd_list);
      fd_elem = list_next(fd_elem))
  {
    _file_descriptor = list_entry(fd_elem, struct file_descriptor, fd_elem);
    if (_file_descriptor->fd == fd)
    {
      break;
    }
  }
  // If fd was not in list return NULL
  if (fd_elem == list_end(&curr_t->open_fd_list))
  {
    return NULL;
  }

  return _file_descriptor;
}