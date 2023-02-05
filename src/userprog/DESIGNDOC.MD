		     +--------------------------+
       	     |		    CS 318		    |
		     | PROJECT 2: USER PROGRAMS	|
		     | 	   DESIGN DOCUMENT     	|
		     +--------------------------+

**---- GROUP ----**

>> Fill in the names and email addresses of your group members.

- Sandil Ranasinghe <ranasinghewmdss.20@cse.mrt.ac.lk>
- Eshan Subasinghe <subasingheeiw.20@cse.mrt.ac.lk>

**---- PRELIMINARIES ----**

>> If you have any preliminary comments on your submission, notes for the
>> TAs, or extra credit, please give them here.

>> Please cite any offline or online sources you consulted while
>> preparing your submission, other than the Pintos documentation, course
>> text, lecture notes, and course staff.

- https://static1.squarespace.com/static/5b18aa0955b02c1de94e4412/t/5b85fad2f950b7b16b7a2ed6/1535507195196/Pintos+Guide

			   ARGUMENT PASSING
			   ================

**---- DATA STRUCTURES ----**

>> A1: Copy here the declaration of each new or changed `struct' or
>> `struct' member, global or static variable, `typedef', or
>> enumeration.  Identify the purpose of each in 25 words or less.

##### **`process.c`**
- `static void start_process (void *cmd_args)`
- `load (const char *cmd_args, void (**eip) (void), void **esp)`  
	changed the name of the arg `file_name_` to `cmd_args` since it was a bit confusing.
- `static bool setup_stack (void **esp, const char *cmd_args)`  
	added an arg to allow passing the string containing the cmd arguments to the function.

**---- ALGORITHMS ----**

>> A2: Briefly describe how you implemented argument parsing.  How do
>> you arrange for the elements of argv[] to be in the right order?
>> How do you avoid overflowing the stack page?

Argument parsing mostly involves getting the arguments passed when calling the process, for
example `myprocess arg1 arg2` and then moving all of that data to the stack and adding the necessary
pointers so that a function / system call that is being called can access those arguments from the
stack frame.

The very first step towards this was to pass the `char *file_name` argument that we receive in
`process_execute` into the `setup_stack` function. We did this by changing the definition of
`setup_stack` as,
```c
static bool setup_stack (void **esp, const char *cmd_args);
```
(*Note: We renamed the arg `file_name_` to `cmd_args` in `process_start` and `load` since that seemed to convey a better explanation of what it contained*)

Inside `setup_stack`, we used `strtok_r` to separate the cmd args into tokens and save them to a
char array while also keeping count of them. Adding an arg to the stack was as simple as moving the
stack pointer down by the required amount and copying the data in the arg to the pointer. `memcpy` 
came in useful here. Once we were done saving the arguments themselves to the stack, we proceeded to 
make sure that the stack pointer was aligned and also added a null pointer to separate the next array. 
Next we proceeded to save an array containing the pointers to the arguments that were saved on the 
stack. 

Note that in both these cases, making sure that they were in the correct order was as simple 
as reversing the array to which we initially saved our args/pointers when iterating through it. 

Finally, we finished by adding a pointer to the array of pointers itself (argv) and also the number
of args (argc).

We didn't try to avoid overflowing at this stage itself, rather letting the kernel throw a page fault
later on and handling it there.

**---- RATIONALE ----**

>> A3: Why does Pintos implement strtok_r() but not strtok()?

Presumably since `strtok_r` can be considered to be thread safe.

>> A4: In Pintos, the kernel separates commands into a executable name
>> and arguments.  In Unix-like systems, the shell does this
>> separation.  Identify at least two advantages of the Unix approach.

It allows the shell to validate the arguments before passing them to the kernel.
It also can slightly reduce the memory used by the kernel to keep track of the initial string of
args and the separated values.

			     SYSTEM CALLS
			     ============

**---- DATA STRUCTURES ----**

>> B1: Copy here the declaration of each new or changed `struct' or
>> `struct' member, global or static variable, `typedef', or
>> enumeration.  Identify the purpose of each in 25 words or less.

- ##### **thread.h - `struct thread` (changed)**  
	```c
	...
		struct list child_list;            // maintain list of children
		struct list_elem child_elem;       // list element for child list of parent
		struct thread *parent_t;           // pointer to parent thread
		struct semaphore init_sema;        // semaphore for parent to wait for child to init
		struct semaphore pre_exit_sema;    // semaphore for parent to wait for child to start exiting and set exit status
		struct semaphore exit_sema;        // semaphore for child to wait for parent to get exit status
		bool status_load_success;          // indicate whether process loaded successfully
		int exit_status;                   // exit status for parents who wait to see

		int next_fd;                       // next file descriptor
		struct list open_fd_list;          // list of open file descriptors held by process
		struct file *process_file; 		   // the file being executed by the process
	...
	```
	Attributes which were required to add the various functionalities required for the syscalls
	were added.
- ##### **syscall.h - `struct file_system_lock` (new)**  
	```c
	struct lock file_system_lock;       // lock for accessing file system
	```
	A lock to make sure that only one process is accessing the file system through syscalls at a time.
- ##### **syscall.h - `struct file_descriptor` (new)**  
	```c
	struct file_descriptor
	{
		struct file *_file;             // pointer to file
		int fd;                         // fid
		struct list_elem fd_elem;       // list elem to add to threads open fds list
	};
	```
	Struct to store data related to a file descriptor.

>> B2: Describe how file descriptors are associated with open files.
>> Are file descriptors unique within the entire OS or just within a
>> single process?

The `struct file_descriptor` maps file descriptors to open files. It contains a pointer to the file
for this purpose. A fd is unique within a single process only.

**---- ALGORITHMS ----**

>> B3: Describe your code for reading and writing user data from the
>> kernel.

When reading user data, depending on the input type, we call either `input_getc` to get keyboard
inputs from STDIN or read a file by getting the corresponding pointer from the file descriptor and
read it using `file_read`.

Similarly, when writing user data, depending on the output type, we call either `putbuf` to write to
STDOUT or write to a file by getting the corresponding pointer from the file descriptor and using 
`file_write`.

(*Note: All file system accesses in syscalls, that is `file_read` and `file_write` are done after acquiring a lock*)

>> B4: Suppose a system call causes a full page (4,096 bytes) of data
>> to be copied from user space into the kernel.  What is the least
>> and the greatest possible number of inspections of the page table
>> (e.g. calls to pagedir_get_page()) that might result?  What about
>> for a system call that only copies 2 bytes of data?  Is there room
>> for improvement in these numbers, and how much?

In the worst case scenario, it would need to be called for each byte, resulting in 4096 and 2 calls
respectively. The least number of calls would depend on the alignment of the data, with 1 or 2 calls
being required to copy 4096 bytes and similar for 2 bytes.

>> B5: Briefly describe your implementation of the "wait" system call
>> and how it interacts with process termination.

Syscall `wait` directly calls `process_wait`, which in turn checks if the thread with the given
thread id is a child of the current thread. If it is a child, `process_wait` then uses a semaphore
to wait until the child thread has called `process_exit` (which is called by `thread_exit` for user
threads), at which point the parent thread can obtain the childs exit status. Finally it lets the
child proceed with the exit (another semaphore is used to make sure the child waits till the parent
gets the exit status) and returns the exit status.

>> B6: Any access to user program memory at a user-specified address
>> can fail due to a bad pointer value.  Such accesses must cause the
>> process to be terminated.  System calls are fraught with such
>> accesses, e.g. a "write" system call requires reading the system
>> call number from the user stack, then each of the call's three
>> arguments, then an arbitrary amount of user memory, and any of
>> these can fail at any point.  This poses a design and
>> error-handling problem: how do you best avoid obscuring the primary
>> function of code in a morass of error-handling?  Furthermore, when
>> an error is detected, how do you ensure that all temporarily
>> allocated resources (locks, buffers, etc.) are freed?  In a few
>> paragraphs, describe the strategy or strategies you adopted for
>> managing these issues.  Give an example.

We use several helper functions to obtain the relevant pointers and validate them.
```c
void validate_ptr(const void *_ptr);
void validate_str(const char *_str);
void validate_buffer(const void *buffer, unsigned size);
int *get_kth_ptr(const void *_ptr, int _k);
```
Using these to obtain and validate pointers keeps the code clean and the logical flow of the syscalls
easy to follow.

**---- SYNCHRONIZATION ----**

>> B7: The "exec" system call returns -1 if loading the new executable
>> fails, so it cannot return before the new executable has completed
>> loading.  How does your code ensure this?  How is the load
>> success/failure status passed back to the thread that calls "exec"?

As mentioned earlier, we use a semaphore to make the parent wait for the child (new executable) to
call process exit (which will be called regardless of completion or failure), at which point we have
an attribute on the child thread which contains its exit status. We use this to obtain exit status
where required for the parent thread (we use another semaphore to make sure the child is not
destroyed until the parent gets the exit status).

>> B8: Consider parent process P with child process C.  How do you
>> ensure proper synchronization and avoid race conditions when P
>> calls wait(C) before C exits?  After C exits?  How do you ensure
>> that all resources are freed in each case?  How about when P
>> terminates without waiting, before C exits?  After C exits?  Are
>> there any special cases?

As mentioned earlier, we use semaphores to achive proper synchronization.
- When P calls wait(C) before C exits, it will wait for C to exit
- When P calls wait(C) after C exits, C will not be able to complete the thread exit until P obtains
	its exit status.

**---- RATIONALE ----**

>> B9: Why did you choose to implement access to user memory from the
>> kernel in the way that you did?

We decided to validate pointers and then access directly access user memory since initially 
implementing it was easier.

>> B10: What advantages or disadvantages can you see to your design
>> for file descriptors?

It's simple to understand. However, if there are many file descriptors for a process, it can be
costly to go through a list to find the relevant one.

>> B11: The default tid_t to pid_t mapping is the identity mapping.
>> If you changed it, what advantages are there to your approach?

Didn't change it.

			   SURVEY QUESTIONS
			   ================

Answering these questions is optional, but it will help us improve the
course in future quarters.  Feel free to tell us anything you
want--these questions are just to spur your thoughts.  You may also
choose to respond anonymously in the course evaluations at the end of
the quarter.

>> In your opinion, was this assignment, or any one of the three problems
>> in it, too easy or too hard?  Did it take too long or too little time?

>> Did you find that working on a particular part of the assignment gave
>> you greater insight into some aspect of OS design?

>> Is there some particular fact or hint we should give students in
>> future quarters to help them solve the problems?  Conversely, did you
>> find any of our guidance to be misleading?

>> Do you have any suggestions for the TAs to more effectively assist
>> students, either for future quarters or the remaining projects?

>> Any other comments?
