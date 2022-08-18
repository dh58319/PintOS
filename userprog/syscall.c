#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "include/vm/vm.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}
// void check_address(void *addr)
// {
// 	struct thread *cur = thread_current();

// 	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(cur->pml4, addr) == NULL)
// 		exit(-1);
// }

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	return 1;
	switch (f->R.rax)
	{
		// case SYS_HALT:
		//  	halt();
		//  	break;
		//  case SYS_EXIT:
		//  	exit(f->R.rdi);
		//  	break;
		//  case SYS_FORK:
		//  	memcpy(&thread_current()->ptf, f, sizeof(struct intr_frame));
		//  	f->R.rax = (uint64_t)fork(f->R.rdi);
		//  	break;
		//  case SYS_CREATE:
		//  	f->R.rax = (uint64_t)create(f->R.rdi, f->R.rsi);
		//  	break;
		//  case SYS_REMOVE:
		//  	f->R.rax = (uint64_t)remove(f->R.rdi);
		//  	break;
		//  case SYS_OPEN:
		//  	f->R.rax = (uint64_t)open(f->R.rdi);
		//  	break;
		//  case SYS_FILESIZE:
		//  	f->R.rax = (uint64_t)filesize(f->R.rdi);
		//  	break;
		//  case SYS_READ:
		//  	f->R.rax = (uint64_t)read(f->R.rdi, f->R.rsi, f->R.rdx);
		//  	break;
		//  case SYS_WRITE:
		//  	f->R.rax = (uint64_t)write(f->R.rdi, f->R.rsi, f->R.rdx);
		//  	break;
		//  case SYS_EXEC:
		//  	exec(f->R.rdi);
		//  	break;
		//  case SYS_WAIT:
		//  	f->R.rax = (uint64_t)wait(f->R.rdi);
		//  	break;
		//  case SYS_SEEK:
		//  	seek(f->R.rdi, f->R.rsi);
		//  	break;
		//  case SYS_TELL:
		//  	f->R.rax = (uint64_t)tell(f->R.rdi);
		//  	break;
		//  case SYS_CLOSE:
		//  	close(f->R.rdi);
		//  	break;
		// default:
		// 	exit(-1);
		// 	break;
	}
}
// void halt(void)
// {
// 	power_off();
// }
// void exit(int status)
// {
// 	struct thread *t = thread_current();
// 	printf("%s: exit%d\n", t->name, status);
// 	thread_exit();
// }
// int fork(const char *thread_name)
// {
// 	check_address(thread_name);
// 	return process_fork(thread_name, &thread_current()->ptf);
// }
// int exec(const char *file_name)
// {
// 	check_address(file_name);

// 	int file_size = strlen(file_name) + 1;
// 	char *fn_copy = palloc_get_page(PAL_ZERO);
// 	if (!fn_copy)
// 	{
// 		exit(-1);
// 		return -1;
// 	}
// 	strlcpy(fn_copy, file_name, file_size);
// 	if (process_exec(fn_copy) == -1)
// 	{
// 		exit(-1);
// 		return -1;
// 	}
// }

// int wait(tid_t pid)
// {
// 	return process_wait(pid);
// }