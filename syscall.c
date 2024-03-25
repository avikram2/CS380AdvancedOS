#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static void check_address (void * address);

#define CHECK_WORD_ADDR(addr) do { \
    check_address((void*)((uint8_t*)(addr))); \
    check_address((void*)((uint8_t*)(addr) + 1)); \
    check_address((void*)((uint8_t*)(addr) + 2)); \
    check_address((void*)((uint8_t*)(addr) + 3)); \
} while (0)


/* Projects 2 and later.
  SYS_HALT,     Halt the operating system. 
  SYS_EXIT,     Terminate this process. 
  SYS_EXEC,     Start another process. 
  SYS_WAIT,     Wait for a child process to die. 
  SYS_CREATE,   Create a file. 
  SYS_REMOVE,   Delete a file. 
  SYS_OPEN,     Open a file. 
  SYS_FILESIZE, Obtain a file's size.
  SYS_READ,     Read from a file. 
  SYS_WRITE,    Write to a file. 
  SYS_SEEK,     Change position in a file. 
  SYS_TELL,     Report current position in a file. 
  SYS_CLOSE,    Close a file. 
  SYS_SYMLINK,  Create soft link 
*/

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void syscall_handler (struct intr_frame *f)
{
  int32_t* stack_word_ptr = (uint32_t*)(f->esp);
  check_address(stack_word_ptr);
  int32_t syscall_number = *(stack_word_ptr);

  switch (syscall_number)
  {
    case(SYS_HALT):
      halt();
      break;
    
    case(SYS_EXIT):
      stack_word_ptr += 1;
      CHECK_WORD_ADDR(stack_word_ptr);
      exit((int)(*stack_word_ptr));
      break;
    
    case (SYS_EXEC):
      stack_word_ptr += 1;
      CHECK_WORD_ADDR(stack_word_ptr);
      // check char pointer
      check_address(stack_word_ptr);
      check_address(*stack_word_ptr);
      f->eax = exec((const char*)(*stack_word_ptr));
      break;

    case (SYS_WAIT):
      stack_word_ptr += 1;
      CHECK_WORD_ADDR(stack_word_ptr);
      f->eax = wait((tid_t)(*stack_word_ptr));
      break;

    case (SYS_WRITE):
      stack_word_ptr += 1;
      printf("%p\n", stack_word_ptr);
      int fd = (*stack_word_ptr);
      stack_word_ptr += 1;
      printf("%p\n", stack_word_ptr);
      check_address(stack_word_ptr);
      check_address(*stack_word_ptr);
      void * buf = (*stack_word_ptr);
      stack_word_ptr += 1;
      printf("%p\n", stack_word_ptr);
      CHECK_WORD_ADDR(stack_word_ptr);
      unsigned length = (*stack_word_ptr);
      f->eax = write(fd, buf, length);
      break;
  }

  exit(0);
}

void print_termination_message(int status)
{
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  return;
}

tid_t exec(const char* cmd_line)
{
 tid_t ret_val = process_execute(cmd_line);
 return ret_val;
}

int write (int fd, const void *buffer, unsigned length)
{
  char * writeBuf = (char*) buffer;
  printf("%u\n", length);
  if (fd == 1)
  {
    //write to console
    putbuf(writeBuf, length);
    return length;
  }


  
}

void exit(int status)
{
  struct thread * cur = thread_current();
  print_termination_message(status);
  process_exit();
  lock_acquire(&(cur->parent_thread->child_process_lock));
  struct list_elem *e;
  if (cur->parent_thread)
  {
  for (e = list_begin (&(cur->parent_thread->child_process_table)); e != list_end (&(cur->parent_thread->child_process_table)); e = list_next (e))
    {
      struct child_process *child_proc = list_entry (e, struct child_process, allelem);
      if (child_proc->child_tid == cur->tid)
      {
        child_proc->child_exit_code = status;
        // set entry for child process to exited and remove from list
        child_proc->proc_status = PROC_EXITED;
        list_remove(e);
        free(child_proc);
        break;
      }
    }
  }
  lock_release(&(cur->parent_thread->child_process_lock));
  // let waiting parent thread continue execution
  sema_up(&(cur->parent_thread->wait_sem));
  thread_exit();
}

int wait (tid_t pid)
{
  return process_wait(pid);
}

void halt(void)
{
  shutdown_power_off();
}

static void check_address(void * address)
{
  /*
    Check if user-passed in pointer is valid, points to user-space
  */
  if (address == NULL)
  {
    exit(-1);
  }
  if (is_user_vaddr(address) == false)
  {
    exit(-1);
  }
  if (pagedir_get_page(thread_current()->pagedir, address) == NULL)
  {
    exit(-1);
  }
}
