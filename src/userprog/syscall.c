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
#include "devices/input.h"

#define CONSOLE_OUTPUT 1
#define KEYBOARD_INPUT 0
#define ERROR_STATUS -1

static void syscall_handler(struct intr_frame *);
static void syscall_exit(int status);
static tid_t syscall_exec(const char *cmd_args);
static int syscall_wait(tid_t tid);
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
void validate_buffer(const void *buffer, unsigned size);
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
  // printf("syscall %d by %s \n", syscall_type, thread_current()->name);

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
    tid_t tid = *get_kth_ptr(f->esp, 1);
    f->eax = syscall_wait(tid);
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
    int fd = *get_kth_ptr(f->esp, 1);
    void *buffer = (void *)*get_kth_ptr(f->esp, 2);
    unsigned size = *((unsigned *)get_kth_ptr(f->esp, 3));
    validate_buffer(buffer, size);

    f->eax = syscall_read(fd, buffer, size);
    break;
  }

  case SYS_WRITE:
  {
    int fd = *get_kth_ptr(f->esp, 1);
    void *buffer = (void *)*get_kth_ptr(f->esp, 2);
    unsigned size = *((unsigned *)get_kth_ptr(f->esp, 3));
    validate_buffer(buffer, size);

    f->eax = syscall_write(fd, buffer, size);
    break;
  }

  case SYS_SEEK:
  {
    int fd = *get_kth_ptr(f->esp, 1);
    unsigned position = *((unsigned *)get_kth_ptr(f->esp, 2));
    syscall_seek(fd, position);
    break;
  }

  case SYS_TELL:
  {
    int fd = *get_kth_ptr(f->esp, 1);
    f->eax = syscall_tell(fd);
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
  t->exit_status = status;
  thread_exit();
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

static int syscall_wait(tid_t tid)
{
  return process_wait(tid);
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

static int syscall_read(int fd, void *buffer, unsigned size)
{
  struct file_descriptor *_file_descriptor;
  int read_size = 0;

  if (fd == KEYBOARD_INPUT)
  {
    for (unsigned i = 0; i < size; i++)
    {
      *((uint8_t *)buffer + i) = input_getc();
      read_size++;
    }
  }
  else if (fd == CONSOLE_OUTPUT)
  {
    return ERROR_STATUS;
  }
  else
  {
    _file_descriptor = get_from_fd(fd);
    if (_file_descriptor == NULL)
    {
      return ERROR_STATUS;
    }

    lock_acquire((&file_system_lock));
    read_size = file_read(_file_descriptor->_file, buffer, size);
    lock_release(&file_system_lock);
  }

  return read_size;
}

static int syscall_write(int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *_file_descriptor;
  char *_buffer = (char *)buffer;
  int written_size = 0;

  if (fd == CONSOLE_OUTPUT)
  {
    putbuf(_buffer, size);
    written_size = size;    
  }
  else if (fd == KEYBOARD_INPUT)
  {
    return ERROR_STATUS;
  }
  else
  {
    _file_descriptor = get_from_fd(fd);
    if (_file_descriptor == NULL)
    {
      return ERROR_STATUS;
    }

    lock_acquire((&file_system_lock));
    written_size = file_write(_file_descriptor->_file, _buffer, size);
    lock_release(&file_system_lock);
  }

  return written_size;
}

static void syscall_seek(int fd, unsigned position)
{
  struct file_descriptor *_file_descriptor = get_from_fd(fd);
  if (_file_descriptor != NULL)
  {
    lock_acquire((&file_system_lock));
    file_seek(_file_descriptor->_file, position);
    lock_release(&file_system_lock);
  }
}

static unsigned syscall_tell(int fd)
{
  unsigned pos = 0;
  struct file_descriptor *_file_descriptor = get_from_fd(fd);
  if (_file_descriptor == NULL)
  {
    return pos;
  }

  lock_acquire((&file_system_lock));
  pos = file_tell(_file_descriptor->_file);
  lock_release(&file_system_lock);

  return pos;
}

static void syscall_close(int fd)
{
  struct file_descriptor *_file_descriptor = get_from_fd(fd);
  if (_file_descriptor != NULL)
  {
    lock_acquire((&file_system_lock));
    file_close(_file_descriptor->_file);
    lock_release(&file_system_lock);

    list_remove(&_file_descriptor->fd_elem);
    free(_file_descriptor);
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

void validate_buffer(const void *buffer, unsigned size)
{
  for (unsigned i = 0; i < size; i++)
  {
    validate_ptr((void *)((char *)buffer + i));
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