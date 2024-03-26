#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static void check_address (const uint8_t * address);

#define CHECK_WORD_ADDR(addr) do { \
    check_address((uint8_t*)(addr))); \
    check_address((uint8_t*)(addr) + 1); \
    check_address((uint8_t*)(addr) + 2); \
    check_address((uint8_t*)(addr) + 3); \
} while (0)


#define CHECK_BOUNDARY(addr, limit) do { \
  check_address((uint8_t*)(addr)); \
  check_address((uint8_t*)(addr) + limit); \
} while (0)


#define CHECK_STR(addr) do { \
  check_address((uint8_t*)(addr)); \
  check_address((uint8_t*)((uint8_t*)(addr) + strlen(addr))); \
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

struct file * get_file_by_fd(int fd)
{
  struct thread * t = thread_current();
  struct list_elem * e;
  for (e = list_begin(&(t->file_descriptor_table)); e != list_end(&(t->file_descriptor_table)); e = list_next(e))
  {
    struct file_descriptor * fd_entry = list_entry (e, struct file_descriptor, allelem);
    if (fd_entry->fd == fd)
    {
      return fd_entry->file_;
    }
  }
  return NULL;
}

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&(filesys_lock));
}

static void syscall_handler (struct intr_frame *);


int write (int fd, const void *buffer, unsigned length)
{
  char * writeBuf = (char*) buffer;
  if (fd == 1)
  {
    //write to console
    putbuf(writeBuf, length);
    return length;
  }

  // write to fd

  struct file * fptr = get_file_by_fd(fd);
  if (fptr == NULL)
  return -1;
  
  int ret_val = 0;
  lock_acquire(&(filesys_lock));
  ret_val = file_write(fptr, buffer, length);
  lock_release(&(filesys_lock));

  return ret_val;
  
}

static void
syscall_handler (struct intr_frame *f) 
{
  int32_t *esp = f->esp;
  CHECK_BOUNDARY(esp, 3);

  	int32_t syscall_num = *esp;

    char * file = NULL;
    int fd = 0;
    unsigned size = 0; 

  	
    switch(syscall_num)
    {
      case (SYS_WRITE):
        esp +=1;
        CHECK_BOUNDARY(esp, 3);
        fd = (*esp);
        esp +=1;
        check_address(esp);
        char * write_buffer = (char*)(*esp);
        esp += 1;
        CHECK_BOUNDARY(esp, 3);
        size = *esp;
        CHECK_BOUNDARY(write_buffer, size);
        f->eax = write(fd, write_buffer, size);
        break;

      case (SYS_EXIT):
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      exit((int)(*esp));
      break;

      case (SYS_HALT):
      halt();
      break;

      case (SYS_EXEC):
      esp += 1;
      check_address(esp);
      char * cmdline = (*esp);
      CHECK_STR(cmdline);
      f->eax = exec(cmdline);
      break;

      case (SYS_CREATE):
      esp +=1;
      check_address(esp);
      file = (*esp);
      CHECK_STR(file);
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      size = *(esp);
      f->eax = create(file, size);
      break;

      case (SYS_REMOVE):
      esp +=1;
      check_address(esp);
      file = (*esp);
      CHECK_STR(file);
      f->eax = remove(file);
      break;

      case (SYS_OPEN):
      esp +=1;
      check_address(esp);
      file = (*esp);
      CHECK_STR(file);
      f->eax = open(file);
      break;

      case (SYS_FILESIZE):
      esp +=1;
      CHECK_BOUNDARY(esp, 3);
      fd = (*esp);
      f->eax = filesize(fd);
      break;

      case (SYS_READ):
      esp +=1;
      CHECK_BOUNDARY(esp, 3);
      fd = (*esp);
      esp += 1;
      check_address(esp);
      void * buffer = (*esp);
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      size = (*esp);
      CHECK_BOUNDARY(buffer, size);
      f->eax = read(fd, buffer, size);
      break;

      case(SYS_SEEK):
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      fd = (*esp);
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      size = (*esp);
      seek(fd, size);
      break;

      case (SYS_TELL):
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      fd = *esp;
      f->eax = tell(fd);
      break;

      case SYS_CLOSE:
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      fd = *esp;
      close(fd);
      break;

      case SYS_WAIT:
      esp += 1;
      CHECK_BOUNDARY(esp, 3);
      tid_t id = *esp;
      f->eax = wait(id);
      break;

      case SYS_SYMLINK:
      esp += 1;
      check_address(esp);
      char * target = *esp;
      CHECK_STR(target);
      esp += 1;
      check_address(esp);
      char * linkpath = *esp;
      CHECK_STR(linkpath);
      f->eax = symlink(target, linkpath);
      break;

      default:
      exit(-1);
      break;
    }
}

void print_termination_message(int status)
{
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  return;
}

int symlink(char * target, char * linkpath)
{
  lock_acquire (&(filesys_lock));
  struct dir* dir = dir_open_root ();
  struct inode* inode = NULL;
  if (dir == NULL)
  {
    lock_release (&(filesys_lock));
  return -1;
  }
  dir_lookup(dir, target, &inode);
  if ((inode)== NULL)
  {
      lock_release (&(filesys_lock));
  return -1;
  }
  bool ret = filesys_symlink(target, linkpath);
  lock_release (&(filesys_lock));

  if (ret)
  return 0;

  return -1;
}

tid_t exec(const char* cmd_line)
{
 tid_t ret_val = process_execute(cmd_line);
 return ret_val;
}

void exit(int status)
{
  struct thread * cur = thread_current();
  struct thread * par = cur->parent_thread;
  print_termination_message(status);

  struct list_elem *e;
  for (e = list_begin (&(cur->file_descriptor_table));
       e != list_end (&(cur->file_descriptor_table)); e = list_next (e))
    {

      if (list_end(e) == true)
      {
        break;
      }

      struct file_descriptor *fd_entry =
          list_entry (e, struct file_descriptor, allelem);
      lock_acquire (&(filesys_lock));
      file_close (fd_entry->file_);
      lock_release (&(filesys_lock));
      list_remove (&(fd_entry->allelem));

    if (list_end(e) == true)
      {
        break;
      }
    }
  lock_acquire(&(par->child_process_lock));
  if (par)
  {
  for (e = list_begin (&(par->child_process_table)); e != list_end (&(par->child_process_table)); e = list_next (e))
    {
      struct child_process *child_proc = list_entry (e, struct child_process, allelem);
      if (child_proc->child_tid == cur->tid)
      {
        child_proc->child_exit_code = status;
        // set entry for child process to exit
        child_proc->proc_status = PROC_EXITED;
        break;
      }
    }
  }
  lock_release(&(par->child_process_lock));
  sema_up(&(par->wait_sem));
  thread_exit();
}

int wait (tid_t pid)
{
  tid_t ret = process_wait(pid);
  return ret;
}

void halt(void)
{
  shutdown_power_off();
}

void close (int fd)
{
  struct thread * t = thread_current();
  struct list_elem * e;
  for (e = list_begin(&(t->file_descriptor_table)); e != list_end(&(t->file_descriptor_table)); e = list_next(e))
  {
    struct file_descriptor * fd_entry = list_entry (e, struct file_descriptor, allelem);
    if (fd_entry->fd == fd)
    {
      list_remove(&(fd_entry->allelem));
      lock_acquire(&(filesys_lock));
      file_close(fd_entry->file_);
      lock_release(&(filesys_lock));
      free(fd_entry);
      return;
    }
  }
  exit(-1);
}

bool create (const char *file, unsigned initial_size)
{
  // acquire global lock to file sys
  lock_acquire(&(filesys_lock));
  bool ret_val = filesys_create(file, initial_size);
  lock_release(&(filesys_lock));
  return ret_val;
}

bool remove (const char * file)
{
  lock_acquire(&(filesys_lock));
  bool ret_val = filesys_remove(file);
  lock_release(&(filesys_lock));
  return ret_val;
}

int open(const char * file)
{
  lock_acquire(&(filesys_lock));
  struct file * ret = filesys_open(file);
  lock_release(&(filesys_lock));
  if (ret == NULL)
  return -1;

  struct file_descriptor * fd_entry = malloc (sizeof (struct file_descriptor));
  fd_entry->fd = thread_current()->next_fd;
  fd_entry->file_ = ret;
  list_push_back(&(thread_current()->file_descriptor_table), &(fd_entry->allelem));
  thread_current()->next_fd++;
  return fd_entry->fd;
}

int filesize(int fd)
{

  struct file * ret = get_file_by_fd(fd);
  if (ret == NULL)
  {
    return -1;
  }
  int ret_val = 0;
  lock_acquire(&(filesys_lock));
  ret_val = file_length(ret);
  lock_release(&(filesys_lock));
  return ret_val; 
}

int read(int fd, void * buffer, unsigned size)
{
  char * buf = buffer;
  int pos = 0;
  if (fd == 0)
  {
    // read from keyboard
    while (pos < size)
    {
    buf[pos] = input_getc();
    ++pos;
    }
    return size;
  }

  struct file * fptr = get_file_by_fd(fd);
  if (fptr == NULL)
  return -1;
  
  int ret_val = 0;
  lock_acquire(&(filesys_lock));
  ret_val = file_read(fptr, buffer, size);
  lock_release(&(filesys_lock));

  return ret_val;
}

void seek (int fd, unsigned position)
{
  struct file * fptr = get_file_by_fd(fd);
  if (fptr == NULL)
  exit(-1);

  lock_acquire(&(filesys_lock));
  file_seek(fptr, position);
  lock_release(&(filesys_lock));

  return;
}

unsigned tell (int fd)
{
  struct file * fptr = get_file_by_fd(fd);
  if (fptr == NULL)
  return -1;

  unsigned ret_val =0;
  lock_acquire(&(filesys_lock));
  ret_val = file_tell(fptr);
  lock_release(&(filesys_lock));
  return ret_val;
}

static void check_address(const uint8_t* address)
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