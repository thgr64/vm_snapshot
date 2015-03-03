/* This file contains the api

*/

#include <stdint.h>
#include <unistd.h>

/// Defines for vm_snapshot flags
/// This flags returns only present pages in human readable form
#define VMS_ONLY_PRESENT_PAGES	1

/// This flags should always be used for fast snapshot acquisition
#define VMS_ALLOW_RAW_OUTPUT	8


#define VMS_HASH_CRC32		16
#define VMS_HASH_CRC32_EX	32
#define VMS_HASH_PATTERN	64
#define VMS_HASH_SHA1		128
#define VMS_HASH_SUPERFAST	256

// one for all
#define DNAME_INLINE_LEN_MAX 40

// only valid for 64 bit
//#define DNAME_INLINE_LEN 32

// only valid for SMP x86
//#define DNAME_INLINE_LEN 36

#define PAGE_NOT_AVAILABLE -42


#define MAX_PIDS			1024

// constants for hash sizes
#define HASH_MD5_SIZE 16
#define HASH_SHA1_SIZE 20
#define HASH_CRC32_SIZE 4
#define HASH_CRC32EX_SIZE 16
#define HASH_SP_SIZE 16
#define HASH_SUPER_SIZE 4

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

/// SnapshotInformation
struct SnapshotInfo
{
	uint32_t version;
	uint32_t longsize;
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

typedef struct SnapshotInfo *VMSNAPSHOT;

//HEAP and STACK 
#define HEAP_MARK	2
#define STACK_MARK  4

/// Helper structure for InputProcessing
struct InputParams
{
	int sleeptime;
	int snapshotcount;
	int autosave;
	int csv;
	int extra;
};

/// Used for HashMap Collisions
struct CollisionInfo
{
	int shareable; // contains shared + sharing_op
	int unshareable;
	int shared;
	int shared_zero;
	int s_heap;
	int s_hrw;
	int s_stack;
	int s_srw;
	int s_anon;
	int s_arw;
	int s_named;
	int s_nrw;
	int sharing_op;
	int sharing_zero;
	int o_heap;
	int o_hrw;
	int o_stack;
	int o_srw;
	int o_anon;
	int o_arw;
	int o_named;
	int o_nrw;
	int o_anon_named;
	int o_named_anon;
	int o_diff_name;
	int shared_counter;
	int named_shared_counter;
};

///
/// @pid: an existing process id
/// @flags: any of the defined flags - can be 0
/// return: on success, it returns a pointer to a snapshot, which must be released
///			on failure, it returns NULL
VMSNAPSHOT TakeSnapshot(int pid, int flags);

///
/// @flags: any of the defined flags - can be 0
/// @count: retruns the VMSNAPSHOT array size
/// return: on success, it returns a pointer to snapshot, which must be released
///			on failure, it returns NULL
VMSNAPSHOT* TakeSnapshots(int flags, int *count);


///
/// @pidflagsstr: a string in the format "existingpid:flags"
/// @len: length of the pidflagsstr
/// return: on success, it returns a pointer to a snapshot, which must be released
///			on failure, it returns NULL
VMSNAPSHOT TakeSnapshotEx(const char* pidflagsstr, int len);

///
/// @handle: a pointer to a snapshot to be released
/// return: 0 on success
///			-1 on failure
int ReleaseSnapshot( VMSNAPSHOT handle);

/// This function loads a snapshot from disk
VMSNAPSHOT LoadSnapshot(const char *path);

/// Function saves snapshot to the file specified
/// @snap: valid snapshot pointer
int SaveSnapshotEx(const char *path, VMSNAPSHOT snap);

/// this automatically chooses a new name for the file depending on the snapshot
/// @snap: valid snapshot pointer
int SaveSnapshot(VMSNAPSHOT snap);

/// It fetches a snapshot from live system or it loads it from disk
/// @input: if string contains .snapshot, it tries to load the snapshot from disk -else it calls TakeSnapshot
/// @len: size of input in bytes
VMSNAPSHOT AcquireSnapshot(const char* input, int len);

int MarkHeapAndStack(VMSNAPSHOT snap);

/// This function takes a pid and suspends the execution of the associated task
int SuspendTask(int pid);

/// This function takes a pid and resumes the previously suspended task
int ResumeTask(int pid);

///Helper function for input processing
/// @argc: parameter of main
/// @argv: parameter of main
/// @result: pointer to InputParams structure, which will held the processed results 
/// returns: the next available index
int ProcessInputParams(int argc, const char *argv[], struct InputParams *result);



///Helper functions for MD5 hashes
/// Prints a MD5 hash in human readable form to stdout and adds a newline
/// @md5: array of 16 bytes representing the hash
void PrintMD5Hash(const unsigned char *md5);

///Helper functions for hashes
/// Prints a hash in human readable form to stdout and adds a newline
/// @hash: array of size bytes representing the hash
/// @size: size of hash
void PrintHash(const unsigned char *hash, int size);

/// Converts a MD5 hash into a human readable form
/// @md5: array of 16 bytes representing the hash
/// @result: buffer that contains at least 33 chars
/// return: returns the pointer to result - no errors
char* ConvertMD5Hash(const unsigned char *md5, char* result);

/// Converts a hash into a human readable form
/// @hash: array of size bytes representing the hash
/// @size: size of hash
/// @result: buffer that contains at least size*2+1 chars
/// return: returns the pointer to result - no errors
char* ConvertHash(const unsigned char *hash, int size, char* result);

/// Compares two MD5 hashes
/// @md5: assumes both have 16 bytes
/// return: 0 if equal, 1 if md5_1 > md5_2, else -1
int CompareMD5Hash(const unsigned char *md5_1, const unsigned char *md5_2);

/// Compares two hashes
/// @hash: assumes both have size bytes
/// return: 0 if equal, 1 if hash1 > hash2, else -1
int CompareHash(const unsigned char *hash1, const unsigned char *hash2, int size);

/// Print Helper Functions

#define MAX_TMP_BUFFER_SIZE 256

/// Prints pages in a valid snapshot
/// @snap: a valid snapshot pointer
/// @start: index into pages - if out of bounds- nothing happens
/// @count: amaount of pages to be printed  - if to many- nothing happens
void PrintPages(VMSNAPSHOT snap, int start, int count);

/// Prints all pages in a valid snapshot's virtual memory area
/// @snap: valid snapshot pointer
/// @vma_index: valid virtual memory area index
void PrintAllPages(VMSNAPSHOT snap, int vma_index);

/// Prints the informations of a valid snapshots' virtual memory informations
/// @snap: valid snapshot pointer
/// @start:
/// @count:
void PrintVMA(VMSNAPSHOT snap, int start, int count);

/// Prints snapshot's Virtual Memory Region and the corresponding pages
/// @snap: valid snapshot
/// @start: a valid index into vms
/// @count: start+count < vm_region_count
void PrintVMAandPages(VMSNAPSHOT snap, int start, int count);

/// Prints snapshot information in csv format
void PrintSnapshotInfo(VMSNAPSHOT snap);

/// Prints humanreadable snapshot information - if snapshot is valid
void PrintSnapshotInfoEx(VMSNAPSHOT snap);

/// Prints the whole snapshot in csv format
void PrintSnapshot(VMSNAPSHOT snap);

/// Prints Virtual Memory Flags in humanreadable form
void PrintVMFlags(unsigned long flags);

/// Prints Virtual Memory Flags in usable form
void PrintVMFlagsEx(unsigned long flags);

/// Prints PageTableEntry flags in humanreadable form
void PrintPTEFlags(unsigned long flags);

/// Prints PageTableEntry flags in more understandable form
void PrintPTEFlagsEx(unsigned long flags);

//TODO Implement PrintPageFlags
void PrintPageFlags(unsigned long flags);

void PrintOptionsHelp();

/// Helper functions for humandreadable vma informations - used by PrintXXX Functions
char* ConvertVMFlags(unsigned long flags, char *result, int size);

char* ConvertVMFlagsToConst(unsigned long flags, char *result, int size);

char* ConvertPTEFlags(unsigned long flags, char *result, int size);

char* ConvertPTEFlagsToConst(unsigned long flags, char *result, int size);

char* ConvertPageFlags(unsigned long flags, char *result, int size);

char* ConvertPageFlagsToConst(unsigned long flags, char *result, int size);


int IsWriteable(unsigned long pte_flags);

const unsigned char* GetZeroPageHash(int flags);

void PrintCollisionInfoHeader();

void PrintCollisionInfo(struct CollisionInfo *info);

int CountSharedPages(VMSNAPSHOT snap);

int CountAnonymousVMA(VMSNAPSHOT snap);
