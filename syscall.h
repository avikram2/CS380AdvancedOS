#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include <stdlib.h>

struct lock filesys_lock;

void syscall_init (void);
void exit (int status);

/* Projects 2 and later. */
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
tid_t exec (const char *file);
int wait (tid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int symlink (char *target, char *linkpath);




#endif /* userprog/syscall.h */
