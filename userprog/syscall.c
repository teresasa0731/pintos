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
typedef int pid_t;
/* Store all syctem calls you may implement in lab01 - user program. */
static void (*syscalls[MAX_SYSCALL])(struct intr_frame *) = {
  [SYS_HALT] = sys_halt,
  [SYS_EXIT] = sys_exit,
  [SYS_EXEC] = sys_exec,
  [SYS_WAIT] = sys_wait,
  [SYS_CREATE] = sys_create,
  [SYS_REMOVE] = sys_remove,
  [SYS_OPEN] = sys_open,
  [SYS_FILESIZE] = sys_filesize,
  [SYS_READ] = sys_read,
  [SYS_WRITE] = sys_write,
  [SYS_SEEK] = sys_seek,
  [SYS_TELL] = sys_tell,
  [SYS_CLOSE] = sys_close
};

/* Task 2:　System call for process. */

void sys_halt(void);                    /* syscall halt. */
void sys_exit(struct intr_frame* f);    /* syscall exit. */
void sys_exec(struct intr_frame* f);    /* syscall exec. */
void sys_wait (struct intr_frame* f);   /*syscall wait */

/* Task 3: System call for file. */
bool sys_create(struct intr_frame* f);  /* syscall create */
void sys_remove(struct intr_frame* f);  /* syscall remove */
void sys_open(struct intr_frame* f);    /* syscall open */
void sys_filesize(struct intr_frame* f);/* syscall filesize */
void sys_read(struct intr_frame* f);    /* syscall read */
void sys_write(struct intr_frame* f);   /* syscall write */
void sys_seek(struct intr_frame* f);    /* syscall seek */
void sys_tell(struct intr_frame* f);    /* syscall tell */
void sys_close(struct intr_frame* f);   /* syscall close */

/* Helper Functions*/

static void syscall_handler (struct intr_frame *);
void *check_ptr(const void *vaddr);
static int get_user(const uint8_t *uaddr);
void invalid_access (void);

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*  Accessing user memory
  code refer from: https://cs162.org/static/proj/pintos-docs/docs/userprog/accessing-user-mem/
*/
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
     : "=&a" (result) : "m" (*uaddr));
  return result;
}
/* Check if the address is vaild:
  1. within in user space
  2. mapped in page directory
  3. readable
*/
void *check_ptr(const void *vaddr)
{
  if (!is_user_vaddr(vaddr))
    invalid_access();

  if (!pagedir_get_page(thread_current()->pagedir), vaddr)
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
  pid_t *pid_ptr = (pid_t *)(f->esp + 1);
  check_ptr(pid_ptr);
  f->eax = process_wait(*pid_ptr);
}

/*
*/




/* Except handler for all invalid conditions.*/
void invalid_access (void)
{
  thread_current()->st_exit = -1;
  thread_exit ();
}

static void syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  
  check_ptr((int *)f->esp + 1);

  int sys_code = *(int *)f->esp;
  if (sys_code < 0 || sys_code >= MAX_SYSCALL)
    invalid_access();

  syscalls[sys_code](f);
}
