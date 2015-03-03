/*
	Kernel module

*/
// used sources:
// Understanding the Linux Kernel (UTLK)
// http://lxr.linux.no
// kernel sources
// http://tldp.org/LDP/lkmpg/2.6/html/ The Linux Kernel Module Programming Guide
//   changed Makefile to CURDIR
// crypto/api-intro.txt for hashing
// http://www.linux-magazin.de/Heft-Abo/Ausgaben/2011/06/Kern-Technik 04.08.11
// procfs: http://buffer.antifork.org/linux/procfs-guide.pdf
// kernel-api: http://www.gnugeneration.com/mirrors/kernel-api/book1.html
// for superfasthash: http://www.azillionmonkeys.com/qed/hash.html
//   LGPL1.2

// debugging
//#define NODEBUG

#ifdef NODEBUG
#define DEBUG
// page releated debugging
#define PDEBUG
// for special page cases
#define SPDEBUG

// virtual memory area related debugging
#define VDEBUG
// hash related debugging
#define HDEBUG
// interface related debugging
#define IDEBUG
#endif

#define PROC_ENTRY_NAME "vm_snapshot"
#define MAX_TMP_BUFFER 128
#define MAX_HASH_SIZE 20 //since SHA1 added

#define VMS_ONLY_PRESENT_PAGES	1
#define VMS_ALLOW_RAW_OUTPUT	8

#define VMS_FILECACHE_ONLY	2

#define VMS_HASH_CRC32		16
#define VMS_HASH_CRC32_EX	32
#define VMS_HASH_PATTERN	64
#define VMS_HASH_SHA1		128
#define VMS_HASH_SUPERFAST	256

#define VMS_RELEASE_SNAPSHOT	1024

#define PAGE_AVAILABLE 1

//defines for output - has worked so far
#define OUTPUT_START	0
#define OUTPUT_END		1
#define OUTPUT_VMR		2
#define OUTPUT_PAGE		4
#define OUTPUT_RAW		64

//BUFFER
#define BUFFER_TOO_SMALL -2


// essential for kernel modules
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/err.h>

// for memory information
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/ioport.h>
#include <asm/page.h>

// helps managing the task struct and related functions
#include <linux/sched.h>

// file information
#include <linux/fs.h>

#include <linux/dcache.h>

// DNAME_INLINE_LEN set to the maximum so far
#define DNAME_INLINE_LEN_MAX 40

#define VM_MODULE_VERSION 0x42

// for proc_fs
#include <linux/proc_fs.h>

// for profiling
#include <linux/timex.h>

// for md5 hashing 
#include <linux/crypto.h>
#include <linux/scatterlist.h>
// for crc32 
#include <linux/crc32.h>


// GPL stuff, to keep the kernel nice and clean
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thorsten");
MODULE_DESCRIPTION("vm_snapshot - ");

//structs

/// PageTableInfo
struct PageTableEntryInfo
{
	//access flags and pfn
	unsigned long pfn;
	unsigned long pte_flags;
	//data from page
	unsigned long page_flags; // page->flags
	unsigned long inode_no; // associated inode
	int reference_count; // _count.counter
	int mapping_count; // _mapping.counter
	int present;
	int reserved;

	//page content hash
	unsigned char hash[20]; //16 for just bytes, 32 for string, should be suitable for md5, crc32 and other patterns

}__attribute__((__packed__));

/// Virtual memory regions
struct VirtualMemoryInfo
{
	unsigned long start_address;
	unsigned long end_address;
	unsigned long flags;
	unsigned long pf_access;
	void * private_data; // maybe it is useful somehow
	unsigned int page_count; 
	unsigned int present_page_count;
	unsigned int swapped_page_count;

	unsigned int page_start_index;

	// other flags
	unsigned long file_offset;
	unsigned long inode_number;
	char file_name[DNAME_INLINE_LEN_MAX]; // stores short names

}__attribute__((__packed__));

//TODO add some snapshot iteration helpers
struct SnapshotIterator
{
	int out_last_offset;
	int out_next_data;
	int out_next_vm_index;
	int out_local_page_index;
	int out_next_page_index;
};

/// SnapshotInformation
struct SnapshotInfo
{
	u32 version;
	u32 longsize;
	int pid; // process id
	int flags; // for future use
	unsigned int timestamp_begin, timestamp_end;

	unsigned long total_pages; // filled by mm_struct.total_vm
	unsigned long locked_pages; // mm_struct.locked_vm
	unsigned long anonymous_pages; // anon_rss - does not exist anymore- so it should be computed or counted or both
	unsigned long shared_pages; // shared_vm

	unsigned long physical_pages; // amount of memory physically allocated for this process - like rss field in ps or top
	unsigned long shared_physical_pages; // amount of physical memory belonging to shared vm_regions
	unsigned long stack_pages; //stack_vm
	unsigned long exec_pages; // exec_vm


	// stack, executable and reserved - might be also interesting
	unsigned long code_start, code_end;
	unsigned long heap_start, heap_end;

	unsigned long data_start, data_end;
	unsigned long stack_start;
	int vm_region_count; // map_count

	unsigned long size_vms;
	unsigned long size_pages;
	unsigned long swapped_pages; // pages that were present but now a swapped out
	unsigned long available_pages; // page count actually included in snapshot

	struct VirtualMemoryInfo *vms; // vm_count - tells how many
	struct PageTableEntryInfo *pages; // total_pages - tells how many or anonymous or shared depending on the flags

}__attribute__((__packed__));


struct input_buffer
{
	int pid;
	int flags;
};


// functions

static int process_input(const char *buffer, struct input_buffer *result);

// hashing functions - ordered form slow to fast
static int hash_page_md5(struct page *pg, char *result);
static int hash_page_sha1(struct page *pg, char *result);
static int hash_page_crc32(struct page *pg, char *result);
static int hash_page_crc32_ex(struct page *pg, char *result);
static int hash_page_pattern(struct page *pg, char *result);
static int hash_page_superfast(struct page *pg, char *result);

uint32_t SuperFastHash (const char * data, int len);

static char* print_page_hash(struct PageTableEntryInfo *ptei, char *result);

static int acquire_mm_struct(int pid, struct mm_struct **result);
static int release_mm_struct(struct mm_struct *result);

static int create_procfs_entry(void);
static int release_procfs_entry(void);

// 
//static int init_snapshot(struct input_buffer *buffer);
static int take_snapshot(struct input_buffer *input, struct SnapshotInfo ** result);
static int take_physical_snapshot(struct input_buffer *input, struct SnapshotInfo ** result);

static int release_global_snapshot(void);
static int is_snapshot_available(void);

static struct SnapshotInfo* allocate_snapshot(int vm_region_count, unsigned long page_count);
static int free_snapshot(struct SnapshotInfo* snapshot);


static int get_next_snapshot_info(struct SnapshotInfo *snapshot, struct SnapshotIterator *iter,char *result, int size);
static int get_next_complete_snapshot_info(struct SnapshotInfo *snapshot, struct SnapshotIterator *iter,char *result, int size);

static int get_next_raw_info(struct SnapshotInfo *snapshot, struct SnapshotIterator *iter, char *buffer, int size);

// helper functions 
static int put_meminfo(struct vm_area_struct *vm_area_ptr, struct VirtualMemoryInfo *vminfo);
static int put_fileinfo(struct file* fs, struct VirtualMemoryInfo *vminfo);
//static int collect_page_data(int index, struct vm_area_struct *vma, struct mm_struct* meminfo, struct VirtualMemoryInfo *vminfo, struct PageTableEntryInfo *pages, unsigned long *res, unsigned long *swapped, int (*hash_page)(struct page *pg, char *result));
static unsigned long collect_complete_page_data(int index, struct mm_struct* meminfo, struct vm_area_struct* vma, struct VirtualMemoryInfo* vminfo, struct PageTableEntryInfo *pages, int (*hash_page)(struct page *pg, char *result));
static unsigned long collect_page_data(int index, struct mm_struct* meminfo, struct vm_area_struct* vma, struct VirtualMemoryInfo* vminfo, struct PageTableEntryInfo *pages, int (*hash_page)(struct page *pg, char *result));
static unsigned long collect_frame_data(unsigned long pfnno, unsigned int count, struct SnapshotInfo *snap, unsigned long pageindex, int (*hash_page)(struct page *pg, char *result));

int (*get_hashfunction(int flags))(struct page *pg, char *result);


// snapshot pointer
static struct SnapshotInfo *gl_snapshot_ptr = NULL;

/// initializes the global data structures and the proc fs entry
int init_module(void)
{
	printk(KERN_INFO "Kernel module vm_snapshot loaded.\n");

	create_procfs_entry();
	return 0;
}

/// cleans the internal data structures
void cleanup_module(void)
{
	release_procfs_entry();
	
	release_global_snapshot();

	printk(KERN_INFO "Kernel module vm_snapshot unloaded.\n");
}

// read_proc: the snapshot will leave through this function
static int read_proc_vm_snapshot(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	static struct SnapshotIterator iterator;
	int in = 0;
	int len=0, ret=0;
	static int pos=0;

#ifdef IDEBUG
	printk(KERN_INFO "%s.read_proc called: 0x%p, %p, %lu, %d\n", PROC_ENTRY_NAME, page, *start, off, count);
#endif

	if (iterator.out_last_offset != off)
	{
		memset(&iterator, 0, sizeof(struct SnapshotIterator));

		pos = 0;
	}
	

	if (is_snapshot_available())
	{
		if (gl_snapshot_ptr->flags & VMS_ALLOW_RAW_OUTPUT)
		{
			if ((count==sizeof(struct SnapshotInfo) || iterator.out_next_data & OUTPUT_RAW))
			{
			
				in = iterator.out_next_data;
				ret = get_next_raw_info(gl_snapshot_ptr, &iterator, page, count);
				if (iterator.out_next_data != in)
				{
				#ifdef DBEUG
					printk("END OF ROAD\n");
				#endif
					*eof = 1;
				}
				iterator.out_last_offset += ret;
				*start = page;
				return ret;
			}
		}
		else
		{
			do
			{
				ret+=len;
				if (gl_snapshot_ptr->flags & VMS_ONLY_PRESENT_PAGES || gl_snapshot_ptr->pid==0)
					len = get_next_snapshot_info(gl_snapshot_ptr, &iterator, page+ret, count-ret);
				else
					len = get_next_complete_snapshot_info(gl_snapshot_ptr, &iterator, page+ret, count-ret);
				
				if (len == -1)
				{
					// this indicates end of file
					*eof = 1;
					//return 0;
					break;
				}
			} while (len!=BUFFER_TOO_SMALL);

			iterator.out_last_offset += ret;
			*start = page;
			return ret;
		}

	}
	else
	{
		printk(KERN_ALERT "%s.read_proc: no snapshot available\n", PROC_ENTRY_NAME);
		return -EINVAL;
	}
	return 0;
}
static DEFINE_RWLOCK(resource_lock);

static struct resource *r_next(struct resource *p, loff_t *pos)
{
		(*pos)++;
		if (p->child)
			return p->child;
		while (!p->sibling && p->parent)
			p = p->parent;
		return p->sibling;
}

static void *r_start(struct resource *p, loff_t *pos)
          __acquires(resource_lock)
{

	  loff_t l = 0;
	  read_lock(&resource_lock);
	  for (p = p->child; p && l < *pos; p = r_next(p, &l))
		;
		return p;
}

static void r_stop(void *v)
          __releases(resource_lock)
{
	read_unlock(&resource_lock);
}

/// write_proc - gets input and triggers snapshot
static int write_proc_vm_snapshot(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	char buf[MAX_TMP_BUFFER+1];
	unsigned long err=0;
	int len = 0;
	struct input_buffer input;


#ifdef IDEBUG
	printk(KERN_INFO "%s.write_proc called: %p, %p, %ld\n", PROC_ENTRY_NAME, file, buffer, count);
#endif

	len = count > MAX_TMP_BUFFER ? MAX_TMP_BUFFER : count;
	err = copy_from_user(buf, buffer, len);

#ifdef IDEBUG
	printk(KERN_INFO "%s: %u bytes copied_from user %.*s err:%lu\n", PROC_ENTRY_NAME, len, len, buf,err);
#endif

	// this function assumes a null terminated string
	buf[len] = '\0';
	if (process_input(buf, &input)==0)
	{
		if (input.flags == VMS_RELEASE_SNAPSHOT)
		{
			release_global_snapshot();
			return 0;
		}

		if (input.pid == 0)
		{

			//printk("Try to take all frames.\n");
			release_global_snapshot();

			if (take_physical_snapshot(&input, &gl_snapshot_ptr)!=0)
			{
				printk(KERN_ALERT "Could not take snapshot of %d with flags %d.\n", input.pid, input.flags);
				release_global_snapshot();
				return -EINVAL;
			}
		
			return count;

			
		}

		// trigger snapshot creation
		if (take_snapshot(&input, &gl_snapshot_ptr)!=0)
		{
			printk(KERN_ALERT "Could not take snapshot of %d with flags %d.\n", input.pid, input.flags);
			release_global_snapshot();
			return -EINVAL;
		}

		//snapshot is available

	}
	else
	{
		printk(KERN_ALERT "%s.write_proc: illegal input\n", PROC_ENTRY_NAME);
		return -EINVAL;
	}

	return count;
}


/// helps extracting data from a snapshot in human readable form
/// assumes all structs exist
static int get_next_complete_snapshot_info(struct SnapshotInfo *snapshot, struct SnapshotIterator *iter,char *result, int size)
{
	static int pc =0;
	int ret=0;
	int pos = 0;
	struct VirtualMemoryInfo *vmi;
	char tmp_hash[MAX_HASH_SIZE*2+1];

	switch (iter->out_next_data)
	{
		case OUTPUT_VMR:

			//printk("%d:%d\n", iter->out_next_vm_index, snapshot->vm_region_count);
			if (iter->out_next_vm_index < snapshot->vm_region_count)
			{
				vmi = &snapshot->vms[iter->out_next_vm_index];
				//V;StartAddr;EndAddr;flags;pg_proto_flags;page_count;present_page_count;filename;
				ret = scnprintf(result, size, " V%d;0x%lx;0x%lx;%lx;%lx;%u;%u;%u;%s;\n", iter->out_next_vm_index, vmi->start_address, vmi->end_address, vmi->flags, vmi->pf_access, vmi->page_count, vmi->present_page_count, vmi->swapped_page_count, vmi->file_name);
		
				//iter->out_next_vm_index++;
				//enum pages associated with Virtual Memory Region
				if (ret+1 < size)
				{

						iter->out_next_data = OUTPUT_PAGE;
				}
				else
				{
					ret = BUFFER_TOO_SMALL;
				}
					
			}
			else
			{
				// end of road
				iter->out_next_data = OUTPUT_END;
				printk("%d PAGES processed:\n" ,pc);
				goto end_of_road;
		
			}
			break;
		case OUTPUT_PAGE:
			//P;PFN;PTE_FLAGS;PAGE_FLAGS;REF_COUNT;MAP_COUNT;HASH;
			pos = iter->out_next_page_index;

			// this skips not present ptes
			if (snapshot->flags & VMS_ONLY_PRESENT_PAGES && snapshot->pages[pos].present <= 0)
				goto try_next;
			pc++;
			ret = scnprintf(result, size, "  P%04d(%04d);%06lx;%lx;%lx;%d;%d;%s;\n", iter->out_local_page_index,iter->out_next_page_index, snapshot->pages[pos].pfn, snapshot->pages[pos].pte_flags, snapshot->pages[pos].page_flags, snapshot->pages[pos].reference_count, snapshot->pages[pos].mapping_count, print_page_hash(&snapshot->pages[pos],tmp_hash));
			if (ret+1 < size)
			{
try_next:
					
				iter->out_next_page_index++;
				iter->out_local_page_index++;
				if (iter->out_local_page_index >= snapshot->vms[iter->out_next_vm_index].page_count)
				{
					// we reached the end of a Virtual Memory Region
					iter->out_local_page_index = 0;
					iter->out_next_vm_index++;
					// continue with the next VMR
					iter->out_next_data = OUTPUT_VMR;
				}
			}
			else
			{
				// BUFFER too small
				ret = BUFFER_TOO_SMALL;
				pc--;
			}
			break;
		case OUTPUT_END:
			//E;
end_of_road:
				
				ret = scnprintf(result, size, "E;\n");

					#ifdef IDEBUG
						printk("END OF ROAD VMI:%d PI:%d\n", iter->out_next_vm_index, iter->out_next_page_index);
					#endif

					return -1;
			break;
		case OUTPUT_START:
		default:
			// S;PID;FLAGS;total;shared;vm_region_count;physical_total;physical_shared;timestamp"
			ret = scnprintf(result, size, "S;%d;%d;%lu;%lu;%u;%lu;%lu;%u;\n", snapshot->pid, snapshot->flags, snapshot->total_pages, snapshot->shared_pages, snapshot->vm_region_count, snapshot->physical_pages, snapshot->available_pages, snapshot->timestamp_end - snapshot->timestamp_begin);
	
			// continue with VMR
			iter->out_next_data = OUTPUT_VMR;
			break;
	}

	return ret;
}

static int get_next_snapshot_info(struct SnapshotInfo *snapshot, struct SnapshotIterator *iter,char *result, int size)
{
	int ret=0;
	int pos = 0;
	struct VirtualMemoryInfo *vmi;
	char tmp_hash[MAX_HASH_SIZE*2+1];

	switch (iter->out_next_data)
	{
		case OUTPUT_VMR:
			if (iter->out_next_vm_index < snapshot->vm_region_count)
			{
				vmi = &snapshot->vms[iter->out_next_vm_index];
				//V;StartAddr;EndAddr;flags;pg_proto_flags;page_count;present_page_count;filename;
				ret = scnprintf(result, size, " V%d;0x%lx;0x%lx;%lx;%lx;%u;%u;%u;%s;\n", iter->out_next_vm_index, vmi->start_address, vmi->end_address, vmi->flags, vmi->pf_access, vmi->page_count, vmi->present_page_count, vmi->swapped_page_count, vmi->file_name);
		
				//enum pages associated with Virtual Memory Region
				if (ret+1 < size)
				{
					iter->out_next_data = OUTPUT_PAGE;
				}
				else
				{
					ret = BUFFER_TOO_SMALL;
				}
					
			}
			else
			{
				// end of road
				iter->out_next_data = OUTPUT_END;
				goto end_of_road;
		
			}
			break;
		case OUTPUT_PAGE:
			//P;PFN;PTE_FLAGS;PAGE_FLAGS;REF_COUNT;MAP_COUNT;HASH;
			pos = iter->out_next_page_index;
			if (snapshot->vms[iter->out_next_vm_index].present_page_count == 0)
				goto next;

			ret = scnprintf(result, size, "  P%04d(%04d);%06lx;%lx;%lx;%d;%d;%s;\n", iter->out_local_page_index,iter->out_next_page_index, snapshot->pages[pos].pfn, snapshot->pages[pos].pte_flags, snapshot->pages[pos].page_flags, snapshot->pages[pos].reference_count, snapshot->pages[pos].mapping_count, print_page_hash(&snapshot->pages[pos],tmp_hash));
			if (ret+1 < size)
			{

				iter->out_next_page_index++;
				iter->out_local_page_index++;
				if (iter->out_local_page_index >= snapshot->vms[iter->out_next_vm_index].present_page_count)
				{
					// we reached the end of a Virtual Memory Region
next:
					iter->out_local_page_index = 0;
					iter->out_next_vm_index++;
					// continue with the next VMR
					iter->out_next_data = OUTPUT_VMR;
				}
			}
			else
			{
				// BUFFER too small
				ret = BUFFER_TOO_SMALL;
			}
			break;
		case OUTPUT_END:
			//E;
end_of_road:
			ret = scnprintf(result, size, "E;\n");

			#ifdef IDEBUG
				printk("END OF ROAD VMI:%d PI:%d\n", iter->out_next_vm_index, iter->out_next_page_index);
			#endif

			return -1;
			break;
		case OUTPUT_START:
		default:
			// S;PID;FLAGS;total;shared;vm_region_count;physical_total;physical_shared;timestamp"
			ret = scnprintf(result, size, "S;%d;%d;%lu;%lu;%u;%lu;%lu;%u;\n", snapshot->pid, snapshot->flags, snapshot->total_pages, snapshot->shared_pages, snapshot->vm_region_count, snapshot->physical_pages, snapshot->available_pages, snapshot->timestamp_end - snapshot->timestamp_begin);
	
			// continue with VMR
			iter->out_next_data = OUTPUT_VMR;
			break;
	}

	return ret;
}


/// This functions helps to get the raw information through the proc fs
/// assumes all structures exist and pointers are initialized
static int get_next_raw_info(struct SnapshotInfo *snapshot, struct SnapshotIterator *iter, char *buffer, int size)
{
	int ret=0;
	char *vms_buf	= (char*)snapshot->vms;
	char *page_buf	= (char*)snapshot->pages;

	if (iter->out_next_data==0)
	{
		memcpy(buffer, snapshot, size);
		ret = size;
		iter->out_next_data = OUTPUT_VMR | OUTPUT_RAW;
		iter->out_next_vm_index = 0;
		iter->out_next_page_index = 0;
	}
	else if (iter->out_next_data & OUTPUT_VMR)
	{
		if (iter->out_next_vm_index + size <= snapshot->size_vms)
		{
			//printk("Copying vmr\n");
			ret = size;
		}
		else
		{
			//printk("End of VMR\n");
			ret = snapshot->size_vms - iter->out_next_vm_index;
			iter->out_next_data = OUTPUT_PAGE | OUTPUT_RAW;
		}

		memcpy(buffer, &vms_buf[iter->out_next_vm_index], ret);
		iter->out_next_vm_index += ret;
		
		//printk("HELP iter: %lu size:%lu\n", iter->out_next_vm_index, snapshot->size_vms);
	}
	else if(iter->out_next_data & OUTPUT_PAGE)
	{

		//printk("PAGE\n");
		if (iter->out_next_page_index + size <= snapshot->size_pages)
		{
			ret = size;
		}
		else
		{
			//printk("End of pages\n");
			ret = snapshot->size_pages - iter->out_next_page_index;
			iter->out_next_data = OUTPUT_END | OUTPUT_RAW;
		}

		memcpy(buffer, &page_buf[iter->out_next_page_index], ret);
		iter->out_next_page_index += ret;

		//printk("HELP iter: %lu size:%lu\n", iter->out_next_page_index, snapshot->size_pages);
	
	}
	else
	{
		printk("We have been called again.\n");
		return 0;
	}
	return ret;
}

/// Creates the proc fs entry and sets up the userrights and stuff
static int create_procfs_entry()
{
	struct proc_dir_entry *entry;
#ifdef IDEBUG
	printk(KERN_INFO "Creating proc fs entry ...\n");
#endif

	// consider security risks 0600 - so only root can access the collected information
	// maybe for testing 0666
	entry = create_proc_entry(PROC_ENTRY_NAME, 0600, NULL);

	if (entry==NULL)
	{
		printk(KERN_ALERT "Cannot create procfs entry %s\n", PROC_ENTRY_NAME);
		return -1;
	}

#ifdef IDEBUG
	printk(KERN_INFO "Proc fs entry created.\n");
#endif

	entry->read_proc	= read_proc_vm_snapshot;
	entry->write_proc	= write_proc_vm_snapshot;


	return 0;
}

/// Releases the proc entry
static int release_procfs_entry()
{

	remove_proc_entry(PROC_ENTRY_NAME, NULL);

#ifdef IDEBUG
	printk(KERN_INFO "Proc fs entry %s removed.\n", PROC_ENTRY_NAME);
#endif

	return 0;
}

/// checks is a snapshot is ready and can be used
static int is_snapshot_available(void)
{
	if (gl_snapshot_ptr==NULL)
		return 0;
	return -1;
}

/// allocates the snapshot
static struct SnapshotInfo* allocate_snapshot(int vm_region_count, unsigned long page_count)
{
	struct SnapshotInfo *snapshot;
	unsigned long vm_region_size, pages_size;

	vm_region_size = sizeof(struct VirtualMemoryInfo)*vm_region_count;
	pages_size = sizeof(struct PageTableEntryInfo)*page_count;

#ifdef DEBUG
	printk(KERN_INFO "allocate_snapshot: sizeof(snapshot)=%lu sizeof(VMI)=%lu vm_region_size: %lu sizeof(PTEI)=%lu pages_size: %lu\n", sizeof(struct SnapshotInfo), sizeof(struct VirtualMemoryInfo), vm_region_size, sizeof(struct PageTableEntryInfo), pages_size);
#endif 

	snapshot = (struct SnapshotInfo*) vmalloc(sizeof(struct SnapshotInfo));
	if (snapshot == NULL)
	{
		printk(KERN_ALERT "OUT_OF_MEMORY: allocating SnapshotInfo\n");
		return NULL;
	}
	memset(snapshot, 0, sizeof(struct SnapshotInfo));

	snapshot->vms = (struct VirtualMemoryInfo*) vmalloc(vm_region_size);
	if (snapshot->vms == NULL)
	{
		vfree(snapshot);
		printk(KERN_ALERT "OUT_OF_MEMORY: allocating VirtualMemoryInfo\n");
		return NULL;
	}
	
	snapshot->pages = (struct PageTableEntryInfo*) vmalloc(pages_size);
	if (snapshot->pages == NULL)
	{
		vfree(snapshot->vms);
		vfree(snapshot);
		printk(KERN_ALERT "OUT_OF_MEMORY: allocating PageTableEntryInfo\n");
		return NULL;
	}

	// zero pages
	memset(snapshot->vms, 0, vm_region_size);
	memset(snapshot->pages, 0, pages_size);
	
	snapshot->size_vms		= vm_region_size;
	snapshot->size_pages	= pages_size;
	snapshot->version		= VM_MODULE_VERSION;
	snapshot->longsize		= sizeof(unsigned long);

	return snapshot;
}

/// frees snapshot virtual memory
static int free_snapshot(struct SnapshotInfo* snapshot)
{
	if (snapshot != NULL)
	{
#ifdef DEBUG
		printk(KERN_INFO "free_snapshot: pages: %p vms: %p\n", snapshot->pages, snapshot->vms);	
#endif
		if (snapshot->pages != NULL)
			vfree(snapshot->pages);
		if (snapshot->vms != NULL)
			vfree(snapshot->vms);

		vfree(snapshot);

		return 0;
	}
	return -1;
}


/// take snapshot
/// assumes input is valid
static int take_snapshot(struct input_buffer *input, struct SnapshotInfo **ptr)
{
	struct mm_struct *meminfo=NULL;
	struct vm_area_struct *vm_area_ptr;
	struct SnapshotInfo *snapshot;
	struct VirtualMemoryInfo *vminfo;

	unsigned long cur_page_count = 0;
	unsigned long shared_page_count = 0;
	unsigned long res=0;
	
	int count=0;

	int (*hashfunction)(struct page *pg, char *result);

#ifdef DEBUG
	printk(KERN_INFO "take_snapshot: \n");
#endif

	if (input==NULL)
	{
#ifdef DEBUG
		printk(KERN_INFO "Wrong input buffer\n");
#endif
		return -1;
	}

#ifdef DEBUG
	printk(KERN_INFO "take_snapshot: taking snapshot(%ld) ... \n", (unsigned long) get_cycles());
#endif

	if (input->pid == 0)
	{
		//TODO do complete snapshot of RAM
		return 0;
	}

	acquire_mm_struct(input->pid, &meminfo);

	printk(KERN_INFO "%p\n", meminfo);
	if (meminfo!=NULL)
	{
#ifdef DEBUG
		printk(KERN_INFO "meminfo: map_count %d total_vm %ld shared: %ld nr_ptes: %ld\n", meminfo->map_count, meminfo->total_vm, meminfo->shared_vm, meminfo->nr_ptes);
#endif 
	}
	else
	{
		printk(KERN_ALERT "Could not get a valid mm_struct.\n");
		return -1;
	}

	// take mmap_sem semaphore
	down_read(&meminfo->mmap_sem);

	// release previous snapshot
	release_global_snapshot();

	// allocate memory for snapshot strucutres
	snapshot = allocate_snapshot(meminfo->map_count, meminfo->total_vm);
	if (snapshot==NULL)
	{
		goto cleanup;
	}

	snapshot->flags			= input->flags;
	snapshot->pid			= input->pid;
	snapshot->locked_pages	= meminfo->locked_vm;
	snapshot->total_pages	= meminfo->total_vm;
	snapshot->shared_pages	= meminfo->shared_vm;
	snapshot->stack_pages	= meminfo->stack_vm;
	snapshot->exec_pages	= meminfo->exec_vm;

	// start and end addresses of heap, stack, init_data, code
	snapshot->code_start	= meminfo->start_code;
	snapshot->code_end		= meminfo->end_code;
	snapshot->stack_start	= meminfo->start_stack;
	snapshot->data_start	= meminfo->start_data;
	snapshot->data_end		= meminfo->end_data;
	snapshot->heap_start	= meminfo->start_brk;
	snapshot->heap_end		= meminfo->brk;


	// timestamp for measurements
	snapshot->timestamp_begin = jiffies_to_msecs(jiffies);

	//take page table spinlock
	spin_lock(&meminfo->page_table_lock);

	hashfunction = get_hashfunction(input->flags);
	
	//take every vm_area_struct and walk them
	vm_area_ptr = meminfo->mmap;
	if (vm_area_ptr != NULL)
	{
		while(vm_area_ptr!=NULL)
		{
			vminfo = &snapshot->vms[count];
			
			put_meminfo(vm_area_ptr, vminfo);

			put_fileinfo(vm_area_ptr->vm_file, vminfo);

			// start page walking here
			res = 0;
			vminfo->page_start_index = cur_page_count;

			// VM_IO pages are dangerous and DEADly
			if (!(vminfo->flags & VM_IO))
			{
				if (snapshot->flags & VMS_ONLY_PRESENT_PAGES)
				{
					cur_page_count += collect_page_data((count+1)*-1, meminfo, vm_area_ptr, vminfo, &snapshot->pages[cur_page_count], hashfunction);
				}
				else
				{
					cur_page_count += collect_complete_page_data((count+1)*-1, meminfo, vm_area_ptr, vminfo, &snapshot->pages[cur_page_count], hashfunction);
				}
				snapshot->physical_pages += vminfo->present_page_count;
				snapshot->swapped_pages  += vminfo->swapped_page_count;

				if (vminfo->flags & VM_SHARED)
					shared_page_count += res;
				}
			// get next vm_area_struct 
			vm_area_ptr = vm_area_ptr->vm_next;
			count++;
		}

#ifdef VDEBUG
		printk(KERN_INFO "vm_snapshot: %d walked of %d %lu physical pages\n", count, meminfo->map_count, snapshot->physical_pages);
#endif
		//snapshot->physical_pages = physical_page_count;
		snapshot->shared_physical_pages = shared_page_count;
		snapshot->vm_region_count = count;
		
		// for every page in vm_area query page table and create hash for each present page
		if (snapshot->flags & VMS_ONLY_PRESENT_PAGES)
		{
			snapshot->available_pages = snapshot->physical_pages;
			snapshot->size_pages = sizeof(struct PageTableEntryInfo) * snapshot->physical_pages;
		}
		else
			snapshot->available_pages = snapshot->total_pages;
	}
	else
	{
		// I am not quite sure if this could happen at all
		printk(KERN_ALERT "Empty memory map found.\n");
		return -1;
	}
		
	// release spinlock
	spin_unlock(&meminfo->page_table_lock);

	// release semaphore
	up_read(&meminfo->mmap_sem);

	//make snapshot available
	gl_snapshot_ptr = snapshot;

	// timestamp
	snapshot->timestamp_end = jiffies_to_msecs(jiffies);

#ifdef DEBUG
	printk(KERN_INFO "vm_snapshot: code(0x%lx-0x%lx) data(0x%lx-0x%lx) heap(0x%lx-0x%lx) stack(0x%lx)\n", snapshot->code_start, snapshot->code_end, snapshot->data_start, snapshot->data_end, snapshot->heap_start, snapshot->heap_end, snapshot->stack_start);
#endif


#ifdef DEBUG
	printk(KERN_INFO "take_snapshot: finsihed.(%ld) tb: %u te: %u\n %u ms", (unsigned long) get_cycles(), snapshot->timestamp_begin, snapshot->timestamp_end, snapshot->timestamp_end - snapshot->timestamp_begin);
#endif

cleanup:
	release_mm_struct(meminfo);

	return 0;
}

/// Frees all structures that might be still alocated
static int release_global_snapshot(void)
{
#ifdef DEBUG
		printk(KERN_INFO "Releasing vm_snapshot(s)\n");
#endif
	if (is_snapshot_available())
	{

		free_snapshot(gl_snapshot_ptr);
		
		gl_snapshot_ptr = NULL;
	}
	return 0;
}

/// processes the information passed by the procfs entry
/// buffer is assumed to be null terminated and readable from kernel
static int process_input(const char *buffer, struct input_buffer *result)
{
	unsigned long res=0;
	char *eofstr;
	if (buffer!=NULL)
	{
		res = simple_strtoul(buffer, &eofstr, 10);
		if (buffer!=eofstr)
		{
			result->pid = res;

			// process flags
			res = simple_strtoul(++eofstr, &eofstr, 16);
			result->flags = res;
		}
		else 
		{
			result->pid = 0;
			result->flags = -1;
			printk(KERN_ALERT "%s: illegal input argument. %s\n", PROC_ENTRY_NAME, buffer);
			return -1;
		}

#ifdef DEBUG
		printk(KERN_INFO "process_input results: %s => pid: %d  flags: %d\n", buffer, result->pid, result->flags);
#endif
		return 0;
	}
	else
	{
		//TODO remove this:  just for testing
		result->pid = 1567;
		result->flags = 0;
		return -1;
	}
}

/// localize the mm_struct, which describes the virtual memory of a process
static int acquire_mm_struct( int pid, struct mm_struct **result)
{

	struct task_struct *task;

	// Localize the task_struct, function documented in UTLK is deprecated and symbole could not be found during module load
	// solution suggested by: http://www.gossamer-threads.com/lists/linux/kernel/1260978

	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task==NULL)
	{
		printk(KERN_ALERT "The corresponding task %d could not be found.\n", pid);
		return -1;
	}

	if (task==current)
	{
		*result = NULL;
		return -1;
	}

#ifdef DEBUG
	printk(KERN_INFO "PID: %d state: %ld\n", pid, task->state);
#endif 

	// fetch mm_struct from task_struct
	*result = get_task_mm(task);
	if (*result==NULL)
	{
		printk(KERN_ALERT "Memory structure could not be found.\n");
		return -1;
	}

#ifdef DEBUG
	printk(KERN_INFO "mm_struct finsished\n");
#endif

	return 0;
}

/// releases the mm_struct
static int release_mm_struct(struct mm_struct *mm)
{	
	if (mm!=NULL)
	{
		// according to linux sources this function should be called after acquiring a mm_struct
		mmput(mm);
#ifdef DEBUG
		printk(KERN_INFO "release_mm_struct: mmput\n");
#endif
		return 0;
	}
	return -1;
}

/// helper function for readability reasons 
/// assumes both are valid pointers
static int put_meminfo(struct vm_area_struct *vm_area_ptr, struct VirtualMemoryInfo *vminfo)
{
	// save required data of memory regions here
	vminfo->start_address	= vm_area_ptr->vm_start;
	vminfo->end_address		= vm_area_ptr->vm_end;
	vminfo->flags			= vm_area_ptr->vm_flags;
	vminfo->file_offset		= vm_area_ptr->vm_pgoff;
#if defined(CONFIG_X86)
	 vminfo->pf_access		= vm_area_ptr->vm_page_prot.pgprot;
#elif defined(CONFIG_ARM)
	// TODO check if this really works and if this returns the correct values
	vminfo->pf_access		= vm_area_ptr->vm_page_prot;
#else
	#warning access rights cannot be handle at this architecture, please add support
#endif
	vminfo->private_data	= vm_area_ptr->vm_private_data;

	vminfo->page_count		= (vminfo->end_address - vminfo->start_address) >> PAGE_SHIFT;

#ifdef VDEBUG
	printk(KERN_INFO "vm_snapshot.vminfo: 0x%016lx 0x%016lx 0x%08lx 0x%08lx\npf_access: %lx private_data %p page_count %u", vminfo->start_address, vminfo->end_address, vminfo->flags, vminfo->file_offset, vminfo->pf_access, vminfo->private_data, vminfo->page_count);
#endif

	return 0;
}

/// helper function to fetch addition information for named memory mappings
static int put_fileinfo(struct file* fs, struct VirtualMemoryInfo* vminfo)
{
	struct path *path_ptr;
	struct dentry *dentry_ptr;
	struct inode *inode_ptr;

	if (fs==NULL)
	{
#ifdef VDEBUG
	printk(KERN_INFO "NO ASSOCIATED FILE.\n");
#endif 
		strcpy(vminfo->file_name, "/anonymous/");
		return -1;
	}

	path_ptr = &fs->f_path;
	if (path_ptr!=NULL)
	{
		dentry_ptr = path_ptr->dentry;
		if (dentry_ptr != NULL)
		{
			strcpy(vminfo->file_name, dentry_ptr->d_iname);
			inode_ptr = dentry_ptr->d_inode;
			if (inode_ptr !=NULL)
			{
				vminfo->inode_number = inode_ptr->i_ino;
			}
		}
	}

#ifdef VDEBUG
	printk(KERN_INFO "FILENAME: %s INODE: %lu\n", vminfo->file_name, vminfo->inode_number);
#endif

	return 0;
}

/// helper: this function walks the page table, derivated form the table table walk described in get_user_pages (in mm/memory.c)
/// this function assumes that all required locks have been taken (as get_user_pages_fast) takes the semaphore
/// the spinlock should be taken too - TODO test both
/// assumes all structures exist
/// @pages - it assumed that enough memory is available
/// return: count of pages 

static unsigned long collect_complete_page_data(int index, struct mm_struct* meminfo, struct vm_area_struct* vma, struct VirtualMemoryInfo* vminfo, struct PageTableEntryInfo* pages, int (*hash_page)(struct page *pg, char *result))
{
	int page_count = 0;
	int failed_count = 0;


	struct page *cur_page;
	// global directory
	pgd_t *pgd;
	// upper directory
	pud_t *pud;
	// middle directory
	pmd_t *pmd;
	// page table entry
	pte_t *pte;

	// start address and increasing
	unsigned long cur_page_addr;
	unsigned long cur_addr = vma->vm_start;
	struct address_space* space;

	do
	{
		pages->present = index;

		cur_page_addr = cur_addr & PAGE_MASK;

		// this fetches the global directory for the current address
		pgd = pgd_offset_gate(meminfo, cur_page_addr);
		if (pgd_none(*pgd))
		{
			printk(KERN_ALERT "PageGlobalDirectory is missing.\n");
			return 0;
		}
		// then we walk down the page table
		pud = pud_offset(pgd, cur_page_addr);
		if (pud_none(*pud))
		{
			#ifdef SPDEBUG
				printk("PageUpperDirectory missing.\n");
			#endif
			return 0;
		}

		pmd = pmd_offset(pud, cur_page_addr);
		if (pmd_none(*pmd))
		{
		#ifdef SPDEBUG
			printk("PageMiddleDirectory missing.\n");
		#endif
			
			goto try_next;
		}

		// map the page table entry - maybe some checks must be done before
		pte = pte_offset_map(pmd, cur_page_addr);
	
		if (pte_none(*pte))
		{
			// according to memory.c
			pte_unmap(pte);
			
			failed_count++;
			goto try_next;
		}

	

		// work with pte
#if defined(CONFIG_X86)
	pages->pte_flags = (unsigned long) pte_flags(*pte);
#elif defined(CONFIG_ARM)
	// TODO replace code to suit the needs of arm architecture
	#warning pte_flags(...) exists only for x86
#else
	#warning pte_flags(...) exists only for x86
#endif

	#ifdef PDEBUG
		printk(KERN_INFO "pages: pfn: %lx flags: %lx\n", pte_pfn(*pte), pages->pte_flags);
	#endif

		if (pte_present(*pte))
		{
			pages->pfn = pte_pfn(*pte);
		
			// work with the page content
			#ifdef PDEBUG
				printk("PAGE_PRESENT\n");
			#endif
			cur_page = pfn_to_page(pages->pfn);
			if (cur_page !=NULL)
			{
				
				pages->present			*= -1;
				pages->page_flags		= cur_page->flags;
				pages->reference_count	= cur_page->_count.counter;
				pages->mapping_count	= cur_page->_mapcount.counter;
				
				if (!PageAnon(cur_page))
				{
					space = (struct address_space*) cur_page->mapping;
					if (space!=NULL)
					{
						if (space->host!=NULL)
						{
							pages->inode_no = space->host->i_ino;
						}
					}
				}

				hash_page(cur_page, pages->hash);
				
				vminfo->present_page_count++;
			}
			else
			{
				printk("empty page\n");
			}
		}
		else
		{
			// pages is swapped out
			pages->pfn = 0;	
			#ifdef PDEBUG
				printk("PAGE_SWAPPED\n");
			#endif
			vminfo->swapped_page_count++;
		}

		// unmap the pte after we are done
		pte_unmap(pte);

try_next:

		// go on to next page
		cur_addr += PAGE_SIZE;
		pages++;
		page_count++;

	} while (cur_addr < vma->vm_end);

	return page_count;
}

static unsigned long collect_page_data(int index, struct mm_struct* meminfo, struct vm_area_struct* vma, struct VirtualMemoryInfo* vminfo, struct PageTableEntryInfo* pages, int (*hash_page)(struct page *pg, char *result))
{
	int page_count = 0;

	struct page *cur_page;
	// global directory
	pgd_t *pgd;
	// upper directory
	pud_t *pud;
	// middle directory
	pmd_t *pmd;
	// page table entry
	pte_t *pte;

	// start address and increasing
	unsigned long cur_page_addr;
	unsigned long cur_addr = vma->vm_start;
	struct address_space* space;

	do
	{
		pages->present = index;

		cur_page_addr = cur_addr & PAGE_MASK;

		// this fetches the global directory for the current address
		pgd = pgd_offset_gate(meminfo, cur_page_addr);
		if (pgd_none(*pgd))
		{
			printk(KERN_ALERT "PageGlobalDirectory is missing.\n");
			return 0;
		}
		// then we walk down the page table
		pud = pud_offset(pgd, cur_page_addr);
		if (pud_none(*pud))
		{
			#ifdef SPDEBUG
				printk("PageUpperDirectory missing.\n");
			#endif
			return 0;
		}

		pmd = pmd_offset(pud, cur_page_addr);
		if (pmd_none(*pmd))
		{
		#ifdef SPDEBUG
			printk("PageMiddleDirectory missing.\n");
		#endif	
			goto try_next;
		}

		// map the page table entry - maybe some checks must be done before
		pte = pte_offset_map(pmd, cur_page_addr);
	
		if (pte_none(*pte))
		{
			// according to memory.c
			pte_unmap(pte);
			goto try_next;
		}

		// work with pte
#if defined(CONFIG_X86)
       pages->pte_flags = (unsigned long) pte_flags(*pte);
#elif defined(CONFIG_ARM)
       // TODO replace code to suit the needs of arm architecture
       #warning pte_flags(...) exists only for x86
#else
       #warning pte_flags(...) exists only for x86
#endif

	#ifdef PDEBUG
		printk(KERN_INFO "pages: pfn: %lx flags: %lx\n", pte_pfn(*pte), pages->pte_flags);
	#endif

		if (pte_present(*pte))
		{
			pages->pfn = pte_pfn(*pte);		

			// work with the page content
			#ifdef PDEBUG
				printk("PAGE_PRESENT\n");
			#endif
			cur_page = pfn_to_page(pages->pfn);
			if (cur_page !=NULL)
			{
				
				pages->present			*= -1;
				pages->page_flags		= cur_page->flags;
				pages->reference_count	= cur_page->_count.counter;
				pages->mapping_count	= cur_page->_mapcount.counter;
	
				if (!PageAnon(cur_page))
				{
					space = (struct address_space*) cur_page->mapping;
					if (space!=NULL)
					{
						if (space->host!=NULL)
						{
							pages->inode_no = space->host->i_ino;
						}
					}
				}
				
				hash_page(cur_page, pages->hash);
				
				vminfo->present_page_count++;

			}
			else
			{
				printk("empty page\n");
			}
		}
		else
		{
			// page is swapped out
			//pages->pfn = 0;
			
			#ifdef PDEBUG
				printk("PAGE_SWAPPED\n");
			#endif
			
			vminfo->swapped_page_count++;
			goto try_next;
		}

		// unmap the pte after we are done
		pte_unmap(pte);

		pages++;
		page_count++;

try_next:

		// go on to next page
		cur_addr += PAGE_SIZE;
	} while (cur_addr < vma->vm_end);

	return page_count;
}

static unsigned long collect_frame_data(unsigned long pfnno, unsigned int count, struct SnapshotInfo *snap, unsigned long pageindex, int (*hash_page)(struct page *pg, char *result))
{
	unsigned long i;
	unsigned long ret=0;
	struct page *cur_page;
	//char buf[64];
	struct PageTableEntryInfo* pages;
	struct address_space* space;

	pages = &snap->pages[pageindex];
	//if (range_is_allowed(pfnno, 
	i = pfnno;

	while (i<pfnno+count)
	{
		//TODO this check might be overdone
		if (pfn_valid(i))
		{
			// page can be accessed
			
			cur_page = pfn_to_page(i);
			if (cur_page !=NULL)
			{
				
				pages->pfn = i;
				pages->present			= 1;
				pages->page_flags		= cur_page->flags;
				pages->reference_count	= cur_page->_count.counter;
				
				
#ifdef PDEBUG
		printk("%d %lx %d\n", i, pages->page_flags, pages->reference_count);
#endif	

				if ((pages->reference_count>0))
				{
					// hashes only present pages
					pages->mapping_count	= cur_page->_mapcount.counter;
					
					if (PageAnon(cur_page))
					{
						snap->physical_pages++;
						if (snap->flags & VMS_FILECACHE_ONLY)
							goto next;
					}
					else
					{
						snap->exec_pages++;
						space = (struct address_space*) cur_page->mapping;
						if (space!=NULL)
						{
							if (space->host!=NULL)
							{
								snap->swapped_pages++;
								pages->inode_no = space->host->i_ino;
								goto hash;
							}
						}
						if (snap->flags & VMS_FILECACHE_ONLY)
							goto next;
					}
		hash:
					hash_page(cur_page, pages->hash);
					
					pages++;
					ret++;
					
				}

			}
		}
		else
		{
			// is io page or invalid
			//printk("Invalid pfn\n");
			snap->locked_pages++;
		}
	next:
		i++;
	}

	return ret;
}

/// creates a md5 hash 
/// pg: is a pointer to a page (PAGE_SIZE)
/// result: must contain at least 16 bytes (128 bit)
static int hash_page_md5(struct page *pg, char *result)
{
#ifdef HDEBUG
	int i;
	cycles_t start,end;
#endif
	struct crypto_hash *tfm;
	struct hash_desc desc;
	static struct scatterlist scatter;
	//void* buffer;
	

	// TODO shorter version??
	//sg_init_table(&scatter, 1);
	//sg_set_page(&scatter, pg, PAGE_SIZE, 0);

#ifdef HDBEUG
	start = get_cycles();
#endif

	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (tfm==NULL)
		return -1;

	desc.tfm = tfm;
	desc.flags = 0;
	
	sg_init_table(&scatter, 1);
	sg_set_page(&scatter, pg, PAGE_SIZE, 0);
	crypto_hash_digest(&desc, &scatter, PAGE_SIZE, result);

#ifdef HDEBUG	
	end = get_cycles();
	printk(KERN_INFO "Hashing: digest cycles: %llu\n", (unsigned long long)end-start);
// not my code
	for (i=0; i <crypto_hash_digestsize(tfm); i++ ) {
                         printk("%02x", (unsigned char) result[i]);
                 }
                 printk("\n");
// end not my code
#endif
	crypto_free_hash(tfm);

	return 0;
}

/// creates a sha1 hash 
/// pg: is a pointer to a page (PAGE_SIZE)
/// result: must contain at least 20 bytes (160 bit)
static int hash_page_sha1(struct page *pg, char *result)
{
#ifdef HDEBUG
	int i;
	cycles_t start,end;
#endif
	struct crypto_hash *tfm;
	struct hash_desc desc;
	static struct scatterlist scatter;

#ifdef HDBEUG
	start = get_cycles();
#endif

	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (tfm==NULL)
		return -1;

	desc.tfm = tfm;
	desc.flags = 0;
	sg_init_table(&scatter, 1);
	sg_set_page(&scatter, pg, PAGE_SIZE, 0);
	crypto_hash_digest(&desc, &scatter, PAGE_SIZE, result);

#ifdef HDEBUG	
	end = get_cycles();
	printk(KERN_INFO "Hashing: digest cycles: %llu\n", (unsigned long long)end-start);
// not my code
	for (i=0; i <crypto_hash_digestsize(tfm); i++ ) {
                         printk("%02x", (unsigned char) result[i]);
                 }
                 printk("\n");
// end not my code
#endif
	crypto_free_hash(tfm);

	return 0;
}

/// transfers the hash into a string - 
/// assumes all parameters are initialized
/// @result has enough space to contain MAX_HASH_SIZE*2 +1 chars
static char* print_page_hash(struct PageTableEntryInfo *ptei, char *result)
{
	int i;
	char *start;
	start = result;
	if (ptei->pfn == 0)
	{
		*result='\0';
		return start;
	}
	for(i=0;i<MAX_HASH_SIZE;i++)
	{
		// cast to unsigned is important and 3 bytes - 2 plus \0 
		result += scnprintf(result, 3, "%02x", (unsigned char)ptei->hash[i]);
	}
	*result='\0';
	return start;
}

/// creates a crc32 checksum 
/// pg: is a pointer to a page (PAGE_SIZE)
/// result: must contain at least 4 bytes (32 bit)
static int hash_page_crc32(struct page *pg, char *result)
{
	char *buffer;
	u32 *res;

	res = (u32*) result;

	buffer = (char*) kmap_atomic(pg);
	if (buffer==NULL)
	{
		printk(KERN_ALERT "Unable to map page.\n");
		return -1;
	}

	*res = crc32(0, buffer, 4096);

	kunmap_atomic(buffer);

	return 0;
}

/// creates 4 crc32 checksums of every 1024 bytes 
/// pg: is a pointer to a page (PAGE_SIZE)
/// result: must contain at least 16 bytes (128 bit)
static int hash_page_crc32_ex(struct page *pg, char *result)
{
	char *buffer;
	u32 *res;

	res = (u32*) result;

	buffer = (char*) kmap_atomic(pg);
	if (buffer==NULL)
	{
		printk(KERN_ALERT "Unable to map page.\n");
		return -1;
	}

	// every 1024 bytes of every page are 'hashed'
	// more of the internal structure of a page is conserved
	*res = crc32(0, buffer, 1024);
	res++;
	buffer+=1024;
	*res = crc32(0, buffer, 1024);
	res++;
	buffer+=1024;
	*res = crc32(0, buffer, 1024);
	res++;
	buffer+=1024;
	*res = crc32(0, buffer, 1024);

	kunmap_atomic(buffer);

	return 0;
}

/// pg: is a pointer to a page (PAGE_SIZE)
/// result: must contain at least 16 bytes (128 bit)
static int hash_page_pattern(struct page *pg, char *result)
{
	char *buffer;
	int i;

	buffer = (char*) kmap_atomic(pg);
	if (buffer==NULL)
	{
		printk(KERN_ALERT "Unable to map page.\n");
		return -1;
	}

	for (i=0;i<12;i++)
	{
		// get every 2^i byte
		result[i] = buffer[1<<i];
	}

	// some patterns might be better than others
	result[12] = buffer[42];
	result[13] = buffer[420];
	result[14] = buffer[840];
	result[15] = buffer[3680];
	
	kunmap_atomic(buffer);

	return 0;
}

/// pg: is a pointer to a page (PAGE_SIZE)
/// result: must contain at least 4 bytes (32 bit)
static int hash_page_superfast(struct page *pg, char *result)
{
	char *buffer;
	uint32_t *res;

	buffer = (char*) kmap_atomic(pg);
	if (buffer==NULL)
	{
		printk(KERN_ALERT "Unable to map page.\n");
		return -1;
	}

	res = (u32*) result;
	*res = SuperFastHash(buffer, PAGE_SIZE);

	kunmap_atomic(buffer);
	return 0;
}

#define get16bits(d) (*((const uint16_t *) (d)))

//TODO implement SuperFastHash Not implemented yet
uint32_t SuperFastHash (const char * data, int len) 
{
uint32_t hash = len, tmp;
int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

int (*get_hashfunction(int flags))(struct page *pg, char *result)
{

	if (flags & VMS_HASH_CRC32)
	{
#ifdef IDEBUG
		printk(KERN_INFO "Using hash_page_crc32.\n");
#endif
		return hash_page_crc32;
	}
	else if (flags & VMS_HASH_CRC32_EX)
	{
#ifdef IDEBUG
		printk(KERN_INFO "Using hash_page_crc32_ex.\n");
#endif
		return hash_page_crc32_ex;
	}
	else if (flags & VMS_HASH_PATTERN)
	{
#ifdef IDEBUG
		printk(KERN_INFO "Using hash_page_pattern.\n");
#endif
		return hash_page_pattern;
	}
	else if (flags & VMS_HASH_SHA1)
	{
#ifdef IDEBUG
		printk(KERN_INFO "Using hash_page_sha1.\n");
#endif
		return hash_page_sha1;
	}
	else if (flags & VMS_HASH_SUPERFAST)
	{
#ifdef IDEBUG
		printk(KERN_INFO "Using hash_page_superfast.\n");
#endif
		return hash_page_superfast;
	}
	else
	{
#ifdef IDEBUG
		printk(KERN_INFO "Using hash_page_md5.\n");
#endif
		return hash_page_md5;
	}

}

static int take_physical_snapshot(struct input_buffer *input, struct SnapshotInfo ** result)
{
	struct resource *t;
	struct resource ram[16];
	struct SnapshotInfo *snap;
	int sys_ram_regions=0;
	int i;
	int (*hashfunction)(struct page *pg, char *result);
	loff_t pos=0;

	t = r_start(&iomem_resource, &pos);
	while (t!=NULL)
	{
		//t = r_next(t, &pos);
		if (strcmp(t->name, "System RAM")==0)
		{
			printk("%lx - %lx %s - %lx\n", (long unsigned int)t->start,(long unsigned int) t->end,  t->name, t->flags);
			ram[sys_ram_regions] = *t;
			sys_ram_regions++;
		}
		t = t->sibling;
		pos++;
	}
	r_stop(t);
	printk("SysRamCount: %d\n", sys_ram_regions);

	snap = allocate_snapshot(sys_ram_regions, totalram_pages);
	//memset(snap, 0, sizeof(SnapshotInfo));
	snap->pid = 0;
	snap->flags = input->flags;
	snap->available_pages = 0;
	snap->total_pages = totalram_pages;
	snap->vm_region_count = sys_ram_regions;

			
	hashfunction = get_hashfunction(input->flags);


	snap->timestamp_begin = jiffies_to_msecs(jiffies);
			
	for (i=0;i<sys_ram_regions;i++)
	{
		snap->vms[i].start_address = ram[i].start;
		snap->vms[i].end_address = ram[i].end;
		snap->vms[i].page_count = (ram[i].end - ram[i].start)/PAGE_SIZE;
		strcpy(snap->vms[i].file_name, "System RAM");
		snap->vms[i].present_page_count = collect_frame_data(ram[i].start/PAGE_SIZE, snap->vms[i].page_count, snap, snap->available_pages,  hashfunction);
		snap->available_pages += snap->vms[i].present_page_count;

	}

	snap->timestamp_end = jiffies_to_msecs(jiffies);

	snap->size_pages = sizeof(struct PageTableEntryInfo) * snap->available_pages;
	
	//make snapshot available
	gl_snapshot_ptr = snap;

	return 0;
}