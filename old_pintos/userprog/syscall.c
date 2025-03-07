#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <devices/shutdown.h>

#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>

#define MAX_SYSCALL 20

// Teresa

/* Task 2:　System call for process. */

void sys_halt(void);                    /* syscall halt. */
void sys_exit(struct intr_frame* f);    /* syscall exit. */
void sys_exec(struct intr_frame* f);    /* syscall exec. */
void sys_wait(struct intr_frame* f);    /* syscall wait */

/* Task 3: System call for file. */
void sys_create(struct intr_frame* f);  /* syscall create */
void sys_remove(struct intr_frame* f);  /* syscall remove */
void sys_open(struct intr_frame* f);    /* syscall open */
void sys_filesize(struct intr_frame* f);/* syscall filesize */
void sys_read(struct intr_frame* f);    /* syscall read */
void sys_write(struct intr_frame* f);   /* syscall write */
void sys_seek(struct intr_frame* f);    /* syscall seek */
void sys_tell(struct intr_frame* f);    /* syscall tell */
void sys_close(struct intr_frame* f);   /* syscall close */

/* Store all syctem calls you may implement in lab01 - user program. */
static void (*syscalls[MAX_SYSCALL])(struct intr_frame *) = {
  [SYS_HALT] = sys_halt,
  [SYS_EXIT] = sys_exit,
  [SYS_EXEC] = sys_exec,
  [SYS_WAIT] = sys_wait,
  // [SYS_CREATE] = sys_create,
  // [SYS_REMOVE] = sys_remove,
  // [SYS_OPEN] = sys_open,
  // [SYS_FILESIZE] = sys_filesize,
  // [SYS_READ] = sys_read,
  [SYS_WRITE] = sys_write,
  // [SYS_SEEK] = sys_seek,
  // [SYS_TELL] = sys_tell,
  // [SYS_CLOSE] = sys_close
};

/* Helper Functions*/

static void syscall_handler (struct intr_frame *);
static void *check_ptr(const void *vaddr);
static int get_user(const uint8_t *uaddr);
static struct open_file *find_file(int fd);
void invalid_access (void);

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred.
  code refer from: https://web.stanford.edu/class/cs140/projects/pintos/pintos_3.html#SEC36
*/
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
     : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* 3.1.5 Accessing User Memory
  Check if the address is vaild:
  1. within in user space
  2. mapped in page directory
  3. readable
*/
static void *check_ptr(const void *vaddr)
{
  if (!is_user_vaddr(vaddr))
    invalid_access();

  if (!pagedir_get_page(thread_current()->pagedir, vaddr))
    invalid_access();

  for (size_t i = 0; i < sizeof(int); i++){
    if(get_user((uint8_t *)vaddr + i) == -1)
      invalid_access(); 
  }
}


/* System Call: void halt (void)
    Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h). 
    This should be seldom used, because you lose some information about possible deadlock situations, etc.
*/
void sys_halt(void)
{
  shutdown_power_off();
}

/* System Call: void exit (int status)
    Terminates the current user program, returning status to the kernel. 
    If the process’s parent waits for it (see below), this is the status that will be returned. 
    Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
void sys_exit(struct intr_frame* f)
{
  int *status_ptr = (int *)f->esp + 1;
  check_ptr(status_ptr);
  thread_current()->st_exit = *status_ptr;
  thread_exit();
}

/* System Call: pid_t exec (const char *cmd_line)
    Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process’s program id (pid). 
    Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
    Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. 
    You must use appropriate synchronization to ensure this.
*/
void sys_exec(struct intr_frame* f)
{
  char **cmd_ptr = (char **)f->esp + 1;
  check_ptr(cmd_ptr);
  check_ptr(*cmd_ptr);
  f->eax = process_execute(*cmd_ptr); // return valid pid or -1
}

/* System Call: int wait (pid_t pid)
    Waits for a child process pid and retrieves the child’s exit status.
    If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. 
    If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. 
    It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait,
    but the kernel must still allow the parent to retrieve its child’s exit status, or learn that the child was terminated by the kernel.
*/
void sys_wait(struct intr_frame* f)
{
  tid_t *pid_ptr = (tid_t *)(f->esp + 1);
  check_ptr(pid_ptr);
  f->eax = process_wait(*pid_ptr);
}

/* System Call: bool create (const char *file, unsigned initial_size)
    Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. 
    Creating a new file does not open it: opening the new file is a separate operation which would require a open system call.
*/
// void sys_create(struct intr_frame* f)
// {
//   uint32_t *user_ptr = f->esp;
//   check_ptr2 (user_ptr + 5);
//   check_ptr2 (*(user_ptr + 4));
//   *user_ptr++;
//   acquire_lock_f ();
//   f->eax = filesys_create ((const char *)*user_ptr, *(user_ptr+1));
//   release_lock_f ();
// }


/* System Call: int write (int fd, const void *buffer, unsigned size)
    Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
    Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. 
    The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.
    Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. 
    (It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts.
*/
void sys_write(struct intr_frame* f)
{
  uint32_t *args = (uint32_t)f->esp;

  int fd = args[1];
  const char *buffer = (const char *)args[2];
  off_t size = (off_t)args[3];

  check_ptr(buffer);
  check_ptr(buffer + size - 1);

  if(fd == 1){  // STDOUT
    putbuf(buffer, size);
    f->eax = size;
  }else{
    struct open_file *tmp = find_file(fd);
    if(tmp){
      acquire_file_lock();
      f->eax = file_write(tmp->file, buffer, size);
      release_file_lock();
    }else{
      f->eax = 0;
    }
  }
}

static struct open_file *find_file(int fd)
{
  struct list *files = &thread_current()->files;
  for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e)) {
      struct open_file *f = list_entry(e, struct open_file, elem);
      if (f->fd == fd) {
          return f;
      }
  }
  return NULL;
}


/* Except handler for all invalid conditions.
    If a system call is passed an invalid argument, acceptable options include:
    a. returning an error value (for those calls that return a value)
    b. returning an undefined value
    c. terminating the process.
*/
void invalid_access (void)
{
  thread_current()->st_exit = -1;
  thread_exit ();
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit();
  
  check_ptr((int *)f->esp + 1);

  int sys_code = *(int *)f->esp;
  if (sys_code < 0 || sys_code >= MAX_SYSCALL)
    invalid_access();

  syscalls[sys_code](f);

}
