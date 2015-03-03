
#include "../include/vmsnapshot.h"
#include "../include/vmsnapstr.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <ctype.h>
#include <dirent.h>

#include <signal.h>

//#include <linux/dcache.h>

//#define DEBUG
#define VM_IO           0x00004000
#define TMP_BUFFER_SIZE 64

// helper functions for internal use
void process(const char* string, struct InputParams *result);


VMSNAPSHOT TakeSnapshot(int pid, int flags)
{
	int len;
	char tmp_buffer[TMP_BUFFER_SIZE];

	len = snprintf(tmp_buffer, TMP_BUFFER_SIZE, "%d:%d", pid, flags);

	return TakeSnapshotEx(tmp_buffer, len);
}

VMSNAPSHOT* TakeSnapshots(int flags, int *count)
{
	int pids[MAX_PIDS];
	int ret,i;
	VMSNAPSHOT *snaps;
	DIR *proc;
	struct dirent *entry;
	
	ret = 0;
	proc = opendir("/proc");
	while ( entry = readdir(proc) )
	{
		if (!isdigit(entry->d_name[0]))
			continue;
		pids[ret] = atoi(entry->d_name);

		ret++;
	}

	closedir(proc);

	snaps = (VMSNAPSHOT*) malloc((ret+1)*sizeof(VMSNAPSHOT));

	for (i=0;i<ret;i++)
	{
		snaps[i] = TakeSnapshot(pids[i], flags);
		printf("Snapshoting %d - %p\n", pids[i], snaps[i]);
	}

	*count = ret;
	return snaps;
}


VMSNAPSHOT TakeSnapshotEx(const char* pidflagsstr, int len)
{

#ifndef WIN32

	int file;
	int ret;
	int res;
	int pid;
	char *buf;
	VMSNAPSHOT tmp_snapshot;

	// open proc fs entry
	file = open("/proc/vm_snapshot", O_RDWR);
	
	if (file<0)
	{
		printf("ERROR: Opening file. errno=%d\n", errno);
		return NULL;
	}

	// create snapshot
	ret = write(file, pidflagsstr, len);
	if (ret!=len)
	{
		printf("Could not take snapshot of %s.\n", pidflagsstr);
		return NULL;
	}
	// allocate tmp_snapshot
	tmp_snapshot = (VMSNAPSHOT) malloc(sizeof(struct SnapshotInfo));
	if (tmp_snapshot==NULL)
	{
		printf("ERROR: Out of memory.\n");
		return NULL;
	}

	pid = atol(pidflagsstr);

	// read snapshot
	ret = read(file, tmp_snapshot, sizeof(struct SnapshotInfo));

	if (ret==sizeof(struct SnapshotInfo) && tmp_snapshot->pid == pid)
	{
		// allocate memory to get pages and vmr
		tmp_snapshot->vms = (struct VirtualMemoryInfo*) malloc(tmp_snapshot->size_vms);
		if (tmp_snapshot->vms==NULL)
		{
			printf("ERROR: Out of memory. (vms)\n");
			free(tmp_snapshot);
			return NULL;
		}

#ifdef DEBUG
		printf("Allocated %lu bytes for vms.\n", tmp_snapshot->size_vms);
#endif

		tmp_snapshot->pages = (struct PageTableEntryInfo*) malloc(tmp_snapshot->size_pages);
		if (tmp_snapshot->pages==NULL)
		{
			printf("ERROR: Out of memory. (pages)\n");
			free(tmp_snapshot->vms);
			free(tmp_snapshot);
			return NULL;
		}

#ifdef DEBUG
		printf("Allocated %lu bytes for pages.\n", tmp_snapshot->size_pages);
#endif

		// start fetching RAWDATA from kernel
		
		// fetching VirtualMemoryRegion Informations
		ret = 0;
		int fetch_size = 4096;
		if (tmp_snapshot->size_vms < fetch_size)
			fetch_size = tmp_snapshot->size_vms;

		buf = (char*) tmp_snapshot->vms;
		res = 0;
		do
		{
			buf += ret;
			ret = read(file, buf, fetch_size);
#ifdef DEBUG
			res += ret;
#endif
		} while( ret>=fetch_size);


#ifdef DEBUG
		printf("%d bytes copied for vms.\n", res);

		for (int i=0;i<tmp_snapshot->vm_region_count;i++)
		{
			printf("%s\n", tmp_snapshot->vms[i].file_name);
		}
#endif
		// fetching PageTable Information
		ret = 0;
		res = 0;
		buf = (char*) tmp_snapshot->pages;
		do
		{
			buf += ret;
			ret = read(file, buf, 4096);
#ifdef DEBUG
			res += ret;
#endif
		} while( ret>=4096);

#ifdef DEBUG
		printf("%d bytes copied for pages.\n", res);
		for (int i=0;i<tmp_snapshot->available_pages;i++)
		{
			printf("%lx ", tmp_snapshot->pages[i].pfn);
		}
		
		printf("\n");
#endif 
	}
	else
	{
		printf("Incompatibility between vm_snapshot module and userland component detected. %d=%ld\n", ret, (long int)sizeof(struct SnapshotInfo));
	}

	// close file
	close(file);

	return tmp_snapshot;

#else
	// for future use
	return 0;
#endif
}

int ReleaseSnapshot(VMSNAPSHOT handle)
{
#ifndef WIN32
	// release memory
	if (handle!=NULL)
	{
		if (handle->pages!=NULL)
			free(handle->pages);
		if (handle->vms!=NULL)
			free(handle->vms);
		free(handle);
		return 0;
	}
	return -1;
#else
	// for future use
#endif
}

int ProcessInputParams(int argc, const char* argv[], struct InputParams *result)
{
	int i;
	int index=1;
	if (argc < 2)
	{
		//PrintOptionsHelp();
		return 0;
	}

	result->snapshotcount	=1;	
	result->sleeptime	=0;
	result->autosave	=0;
	result->csv		=0;
	result->extra	=0;
	for (i=1;i<argc;i++)
	{
		if (argv[i][0]=='-')
		{
			if (strlen(argv[i])>=2)
				process(&argv[i][1], result);
			index++;
		}
		else
			break;
	}
	
	return index;
}

// for internal use only
void process(const char* string, struct InputParams *result)
{
	long int ret;
	// -t=1000 -n=200

//	printf("%s\n", string);	

	if (string[0]=='t')
	{
		ret = atol(&string[2]);
		if (ret==0)
			result->sleeptime=0;
		else
			result->sleeptime=ret;
	}
	else if (string[0]=='n')
	{
		ret = atol(&string[2]);
		if (ret==0)
			result->snapshotcount=1;
		else
			result->snapshotcount=ret;	
	}
	else if (string[0]=='s')
	{
		result->autosave=1;
	}
	else if (string[0]=='c')
	{
		result->csv = 1;
	}
	else if (string[0]=='x')
	{
		result->extra = 1;
	}
	else
	{
		printf("Unsupported.\n");
	}
}

VMSNAPSHOT AcquireSnapshot(const char* input, int len)
{
	//printf("Input: %s\n",input);
	if (strstr(input,".snapshot")!=NULL)
	{
		//printf("Loading...\n");
		return LoadSnapshot(input);
	}
	else
		return TakeSnapshotEx(input, len);
}

int MarkHeapAndStack(VMSNAPSHOT snap)
{
	int i;
	int ret=0;
	if (snap==NULL)
		return -1;

	for (i=0;i<snap->vm_region_count;i++)
	{
		if (snap->vms[i].start_address==snap->stack_start)
		{
			//printf("Stack found. %s\n", snap->vms[i].file_name);
			snap->vms[i].file_name[0] = STACK_MARK;
			snap->vms[i].file_name[1] = '\0';
			ret+=1;
			continue;
		}
		if (snap->vms[i].start_address==snap->heap_start)
		{
			//printf("Heap found. %s\n", snap->vms[i].file_name);
			snap->vms[i].file_name[0] = HEAP_MARK;
			snap->vms[i].file_name[1] = '\0';
			ret+=2;
			continue;
		}
	
	}

	return ret;
}

void PrintOptionsHelp()
{
	printf("Options:\n");
	printf("-t=\tTime between snapshots in seconds - -t=10\n");
	printf("-n=\tAmount of snapshots that should be taken - -n=5\n");
	printf("-s \tAutosaves snapshots into current working directory\n");
	printf("-c \tOutput is in csv format\n");
}


int SuspendTask(int pid)
{
#ifdef WIN32
	
#else
	kill(pid, SIGSTOP);
#endif
	return 0;
}

int ResumeTask(int pid)
{
	kill(pid, SIGCONT);
	return 0;
}

/// Prints a MD5 hash in human readable form to stdout and adds a newline
/// @md5: array of 16 bytes representing the hash
void PrintMD5Hash(const unsigned char *md5)
{
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
}

void PrintHash(const unsigned char *hash, int size)
{
	int i;
	for (i=0;i<size;i++)
	{
		printf("%02x", hash[i]);
	}
	printf("\n");
}

/// Converts a MD5 hash into a human readable form
/// @md5: array of 16 bytes representing the hash
/// @result: buffer that contains at least 33 chars
/// return: returns the pointer to result - no errors
char* ConvertMD5Hash(const unsigned char *md5, char *result)
{
	int i;
	int tlen;
	char *start;
	start = result;

	result += snprintf(result, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7], md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);

	*result='\0';
	return start;
}

char* ConvertHash(const unsigned char *hash, int size, char* result)
{
	int tlen;
	char *start;
	start = result;

	result += snprintf(result, size*2+1, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);

	*result='\0';
	return start;
}

int CompareMD5Hash(const unsigned char *md5_1, const unsigned char *md5_2)
{
	int i;
	for (i=0;i<16;i++)
	{
		//TODO check this comparision
		if (md5_1[i]>md5_2[i])
			return 1;
		else if (md5_1[i]<md5_2[i])
			return -1;
	}

	return 0;
}

int CompareHash(const unsigned char *hash1, const unsigned char *hash2, int size)
{
	int i;

	for (i=0;i<size;i++)
	{
		if (hash1[i]>hash2[i])
			return 1;
		else if (hash1[i]<hash2[i])
			return -1;
	}

	return 0;
}


VMSNAPSHOT LoadSnapshot(const char *path)
{
	VMSNAPSHOT snap;
	struct stat info;
	int ret, res;
	char *buffer, *curbuf;
	int file;

	file = open(path, O_RDONLY);
	if (file<0)
	{
		printf("Could not create %s. errno=%d\n", path, errno);
		return NULL;
	}

	// allocate the snapshot
	snap = (VMSNAPSHOT) malloc(sizeof(struct SnapshotInfo));

	
	// fetch the snapshot information
	ret = read(file, snap, sizeof(struct SnapshotInfo));
	if (ret != sizeof(struct SnapshotInfo))
	{
		free(snap);
		printf("File in illegal or in compatible format.\n");
		return NULL;
	}

	if (snap->longsize!=sizeof(unsigned long))// || snap->version!=0x42);
	{
		printf("Incompatible version: sizeof(unsigned long) = %d, but should be %d.\n", (int)sizeof(unsigned long), snap->longsize); 
		close(file);
		free(snap);
		
		return NULL;
	}

	// prepare memory for the whole file
	
	snap->vms = (struct VirtualMemoryInfo*) malloc(snap->size_vms);
	if (snap->vms==NULL)
	{
		printf("ERROR: Out of memory. (vms)\n");
		free(snap);
		return NULL;
	}

#ifdef DEBUG
		printf("Allocated %lu bytes for vms.\n", tmp_snapshot->size_vms);
#endif

	snap->pages = (struct PageTableEntryInfo*) malloc(snap->size_pages);
	if (snap->pages==NULL)
	{
		printf("ERROR: Out of memory. (pages)\n");
		free(snap->vms);
		free(snap);
		return NULL;
	}

#ifdef DEBUG
		printf("Allocated %lu bytes for pages.\n", tmp_snapshot->size_pages);
#endif

	//TODO maybe mapping the file to memory is more efficent
	/*ret=fstat(file, &info);
	if (ret<0)
	{
		printf("Could not get file information\n");
		return -1;
	}
	
	
	
	buffer = mmap(0, info.st_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, file, NULL);
	
	if (buffer==NULL)
	{
		printf("Mapping failed.\n");
		return -1;
	}
	
	memcpy(&snap, buffer, sizeof(struct SnapShotinfo));
	
	curbuf = buffer + sizeof(struct SnapshotInfo);
	
	memcpy(&snap->vms, curbuf, snap->size_vms);
	curbuf += snap->size_vma;
	memcpy(&snap->pages, curbuf, snap->size_pages);
	
	mumap(buffer, info.st_size);
	
	close(file);
	*/
	do
	{
		ret = read(file, snap->vms, snap->size_vms);
		if (ret<=0)
		{
			printf("Could not read file.\n");
			return NULL;
		}
		res += ret;
	} while (res < snap->size_vms);

	do
	{
		ret = read(file, snap->pages, snap->size_pages);
		if (ret<=0)
		{
			printf("Could not read file.\n");
			return NULL;
		}

		res += ret;
	} while (res < snap->size_pages);

	close(file);
	
	return snap;
}

int SaveSnapshotEx(const char *path, VMSNAPSHOT snap)
{
	int file;
	int ret, res;

	file = open(path, O_WRONLY | O_CREAT);
	if (file<0)
	{
		printf("Cannot open %s. errno=%d\n", path, errno);
		return -1;
	}

	ret = write(file, snap, sizeof(struct SnapshotInfo));
	if (ret != sizeof(struct SnapshotInfo))
	{
		printf("Unable to write file to disk. ret=%d errno=%d\n", ret, errno);
		return -1;
	}

	ret = 0;
	res = 0;
	do
	{
		ret = write(file, snap->vms, snap->size_vms);
		if (ret<=0)
		{
			printf("Could not write file.\n");
			return -1;
		}
		res += ret;
	} while (res < snap->size_vms);

	ret = 0;
	res = 0;
	do
	{
		ret = write(file, snap->pages, snap->size_pages);
		if (ret<=0)
		{
			printf("Could not write file.\n");
			return -1;
		}

		res += ret;
	} while(res < snap->size_pages);

	close(file);
	return 0;

}

int SaveSnapshot(VMSNAPSHOT snap)
{
	char tmp_path[128];

	snprintf(tmp_path,128, "%d-%x.snapshot", snap->pid, (int)snap->timestamp_begin);

	return SaveSnapshotEx(tmp_path, snap);
}


/// Print Helper Functions

//TODO helper output functions in different header file?
///These function will take the flags parameter of the snapshot
///to determine the kind of output requested
///OUTPUT_RAW might be used for  csv output
///otherwise it will make it more humanreadable by parsing flags

///
void PrintPages(VMSNAPSHOT snap, int start, int count)
{
	struct PageTableEntryInfo *cur_page;
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];

	if (snap==NULL)
		return;

	//Checks if pages are in snapshot range
	if (start >= snap->available_pages || start+count > snap->available_pages)
	{
		printf("error\n");
		return;
	}
	cur_page = &snap->pages[start-1];

	int i=0;
	for (i=0;i<count;i++)
	{
		cur_page++;
		if (snap->flags & VMS_ONLY_PRESENT_PAGES && cur_page->present < 0)
			continue;
	
		printf("%6lx;%3d;%3d;%s;", cur_page->pfn, cur_page->reference_count, cur_page->mapping_count, ConvertPTEFlags(cur_page->pte_flags, tmp_buffer, MAX_TMP_BUFFER_SIZE));
		printf("%s;%lu;", ConvertPageFlags(cur_page->page_flags, tmp_buffer, MAX_TMP_BUFFER_SIZE),cur_page->inode_no);
		if (snap->flags & VMS_HASH_SHA1)
			PrintHash(cur_page->hash, HASH_SHA1_SIZE);
		else
			PrintMD5Hash(cur_page->hash);
	}
}

void PrintAllPages(VMSNAPSHOT snap, int vma_index)
{
	if (snap==NULL)
		return;
	
	if (vma_index >= snap->vm_region_count)
		return;
	if (snap->flags & VMS_ONLY_PRESENT_PAGES)
		PrintPages(snap, snap->vms[vma_index].page_start_index, snap->vms[vma_index].present_page_count);
	else
		PrintPages(snap, snap->vms[vma_index].page_start_index, snap->vms[vma_index].page_count);
}


///
void PrintVMA(VMSNAPSHOT snap, int start, int count)
{
	struct VirtualMemoryInfo *cur_vma;
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];

	if (snap==NULL)
		return;

	//Checks if pages are in snapshot range
	if (start >= snap->vm_region_count || start+count > snap->vm_region_count)
		return;
	
	cur_vma = &snap->vms[start-1];

	int i=0;
	for (i=0;i<count;i++)
	{
		cur_vma++;
		
		printf("%lx;%lx;%s;", cur_vma->start_address, cur_vma->end_address, ConvertPTEFlags(cur_vma->flags, tmp_buffer, MAX_TMP_BUFFER_SIZE));
		printf("%s;", ConvertVMFlags(cur_vma->pf_access, tmp_buffer, MAX_TMP_BUFFER_SIZE));
		printf("%u;%u;%u;%s;\n", cur_vma->page_count, cur_vma->present_page_count, cur_vma->swapped_page_count, cur_vma->file_name);
		
	}
}

///
void PrintVMAandPages(VMSNAPSHOT snap, int start, int count)
{
	int i=0;
	
	if (snap==NULL)
		return;

	if (start >= snap->vm_region_count || start+count > snap->vm_region_count)
		return;
	
	for (i=start;i<start+count;i++)
	{
		PrintVMA(snap, i, 1);
		if (snap->vms[i].flags & ~VM_IO)
			PrintAllPages(snap, i);
	}
}

///
void PrintSnapshotInfo(VMSNAPSHOT snap)
{
	if (snap==NULL)
		return;

	//pid;flags;timestamp;ms;total_pages;physical_pages;swapped_out;available_pages;locked_pages;
	printf("%u;%x;%d;%d;%ld;", snap->pid, snap->flags, snap->timestamp_begin, snap->timestamp_end - snap->timestamp_begin, snap->total_pages);
	printf("%ld;%ld;%ld;", snap->physical_pages, snap->swapped_pages, snap->available_pages);
	printf("%ld;", snap->locked_pages);
	printf("%ld;", snap->swapped_pages);
	//codeS;codeE;codeP;dataS;dataE;heapS;heapE;stackS;stackP;vm_region_count;
	printf("0x%lx;0x%lx;%ld;", snap->code_start, snap->code_end, snap->exec_pages);
	printf("0x%lx;0x%lx;", snap->data_start, snap->data_end);
	printf("0x%lx;0x%lx;", snap->heap_start, snap->heap_end);
	printf("0x%lx;%ld;",snap->stack_start, snap->stack_pages);
	printf("%d;", snap->vm_region_count);
	
};

///
void PrintSnapshotInfoEx(VMSNAPSHOT snap)
{
	if (snap==NULL)
		return;
	if (snap->pid!=0)
	{
		printf("Snapshot of %d with flags %x\n", snap->pid, snap->flags);
		printf("Timestamp:      %u Tock: %d ms\n", snap->timestamp_begin, snap->timestamp_end - snap->timestamp_begin);
		printf("TotalPages:     %ld pages\n", snap->total_pages);
		printf("PhysicalPages:  %ld pages present\n", snap->physical_pages);
		printf("PhysicalPages:  %ld pages swapped out\n", snap->swapped_pages); //TODO create this field
		printf("AvailablePages: %ld pages => %ld bytes\n", snap->available_pages, snap->available_pages * 4096);
		printf("LockedPages:    %ld pages\n", snap->locked_pages);
		printf("SwappedPages:   %ld pages\n", snap->swapped_pages); 
		printf("Executable:     0x%lx - 0x%lx %ld pages\n", snap->code_start, snap->code_end, snap->exec_pages);
		printf("Data:           0x%lx - 0x%lx\n", snap->data_start, snap->data_end);
		printf("Heap:           0x%lx - 0x%lx\n", snap->heap_start, snap->heap_end);
		printf("Stack:          0x%lx %ld pages\n",snap->stack_start, snap->stack_pages);
		printf("Contains %d Virtual Memory Regions\n", snap->vm_region_count);

	}
	else
	{
		printf("Snapshot of physical memory with flags %x\n", snap->flags);
		printf("Timestamp:      %u Tock: %d ms\n", snap->timestamp_begin, snap->timestamp_end - snap->timestamp_begin);
		printf("TotalPages:     %ld pages\n", snap->total_pages);
		printf("AnonymousPages: %ld pages\n", snap->physical_pages);
		printf("ASPages:        %ld pages\n", snap->exec_pages);
		printf("NamedPages:     %ld pages have associated files\n", snap->swapped_pages); //TODO create this field
		printf("AvailablePages: %ld pages => %ld bytes\n", snap->available_pages, snap->available_pages * 4096);
		printf("InvalidPFNs:    %ld PhysicalFrameNumbers\n", snap->locked_pages);
	}
}
///
void PrintSnapshot(VMSNAPSHOT snap)
{
	if (snap==NULL)
		return;
		
	PrintSnapshotInfoEx(snap);
	PrintVMAandPages(snap,0,snap->vm_region_count);
}

void PrintVMFlags(unsigned long flags)
{
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];
	
	printf("%s", ConvertVMFlags(flags, tmp_buffer, MAX_TMP_BUFFER_SIZE));
}

void PrintPTEFlags(unsigned long flags)
{
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];
	
	printf("%s", ConvertPTEFlags(flags, tmp_buffer, MAX_TMP_BUFFER_SIZE));

}

void PrintPageFlags(unsigned long flags)
{
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];
	
	printf("%s", ConvertPageFlags(flags, tmp_buffer, MAX_TMP_BUFFER_SIZE));

}

char* ConvertVMFlags(unsigned long flags, char *result, int size)
{
	char* buf = result;
	int count = size;
	int ret = 0;
	int tflag = 1;
	int i=0;

	for (i=0;i<32;i++)
	{	

		if (count <= 0)
			break;
			
		if (flags & tflag)
		{
			ret = snprintf(buf, count, "%s", VMFLAGSTOCHAR[i]);
			buf+=ret;
			count-=ret;
		}
		else
		{
			ret = snprintf(buf, count, "-");
			buf+=ret;
			count-=ret;
		}
		

		tflag <<=1;
	}
	
	return result;
}


char* ConvertVMFlagsToConst(unsigned long flags, char *result, int size)
{
	char* buf = result;
	int count = size;
	int ret = 0;
	int tflag = 1;
	int i=0;

	for (i=0;i<32;i++)
	{	

		if (count <= 0)
			break;
			
		if (flags & tflag)
		{
			ret = snprintf(buf, count, " | %s", VMFLAGSTOSTRING[i]);
			buf+=ret;
			count-=ret;
		}

		tflag <<=1;
	}
	
	return result;
}

char* ConvertPTEFlags(unsigned long flags, char *result, int size)
{
	char* buf = result;
	int count = size;
	int ret = 0;
	int tflag = 1;
	int i=0;

	for (i=0;i<13;i++)
	{	

		if (count <= 0)
			break;
			
		if (flags & tflag)
		{
			ret = snprintf(buf, count, "%s", PTEFLAGSTOCHAR[i]);
			buf+=ret;
			count-=ret;
		}
		else
		{
			ret = snprintf(buf, count, "--");
			buf+=ret;
			count-=ret;
		}
		

		tflag <<=1;
	}
	
	if (flags & (1llu<<63))
	{
		ret = snprintf(buf, count, "NX");
	}
	else
		ret = snprintf(buf, count, "--");

	return result;
}


char* ConvertPTEFlagsToConst(unsigned long flags, char *result, int size)
{
	char* buf = result;
	int count = size;
	int ret = 0;
	int tflag = 1;
	int i=0;

	for (i=0;i<13;i++)
	{	

		if (count <= 0)
			break;
			
		if (flags & tflag)
		{
			ret = snprintf(buf, count, " %s", PTEFLAGSTOSTRING[i]);
			buf+=ret;
			count-=ret;
		}

		tflag <<=1;
	}
	
	if (flags & (1llu<<63))
	{
		ret = snprintf(buf, count, "NX");
	}
	return result;
}

char* ConvertPageFlags(unsigned long flags, char *result, int size)
{
	char* buf = result;
	int count = size;
	int ret = 0;
	int tflag = 1;
	int i=0;

	for (i=0;i<26;i++)
	{	

		if (count <= 0)
			break;
				
		if (flags & tflag)
		{
			ret = snprintf(buf, count, "%s", PAGEFLAGSTOCHAR[i]);
			buf+=ret;
			count-=ret;
		}
		else
		{
			ret = snprintf(buf, count, "-");
			buf+=ret;
			count-=ret;
		}
		

		tflag <<=1;
	}
	
	return result;
}

char* ConvertPageFlagsToConst(unsigned long flags, char *result, int size)
{
	char* buf = result;
	int count = size;
	int ret = 0;
	int tflag = 1;
	int i=0;

	for (i=0;i<26;i++)
	{	

		if (count <= 0)
			break;
			
		if (flags & tflag)
		{
			ret = snprintf(buf, count, " %s", PAGEFLAGSTOSTRING[i]);
			buf+=ret;
			count-=ret;
		}

		tflag <<=1;
	}
	
	return result;
}

const unsigned char* GetZeroPageHash(int flags)
{
	if (flags & VMS_HASH_CRC32)
		return (const unsigned char *)ZEROPAGEHASHES[1];
	else if (flags & VMS_HASH_CRC32_EX)
		return (const unsigned char *) ZEROPAGEHASHES[2];
	else if (flags & VMS_HASH_SUPERFAST)
		return (const unsigned char *) ZEROPAGEHASHES[3];
	else if (flags & VMS_HASH_PATTERN)
		return (const unsigned char *) ZEROPAGEHASHES[4];
	else if (flags & VMS_HASH_SHA1)
		return (const unsigned char *) ZEROPAGEHASHES[5];
	else
		return (const unsigned char *) ZEROPAGEHASHES[0];
}

int IsWriteable(unsigned long pte_flags)
{
	return pte_flags & 2;
}

void PrintCollisionInfoHeader()
{
	printf("Unshareable;Shareable;Shared;SharedZeroPages;stack;stack rw;heap;heap rw;anonymous;anon rw;named;named rw;Sharing Op;SharingOpZeroPages;stack;stack rw;heap;heap rw;anonymous;anon rw;named;named rw;;;;shared count;named shared count;");
}

void PrintCollisionInfo(struct CollisionInfo *info)
{
	printf("%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;",info->unshareable, info->shareable, info->shared, info->shared_zero, info->s_stack, info->s_srw, info->s_heap, info->s_hrw, info->s_anon, info->s_arw, info->s_named, info->s_nrw, info->sharing_op, info->sharing_zero, info->o_stack, info->o_srw, info->o_heap, info->o_hrw, info->o_anon, info->o_arw, info->o_named, info->o_nrw, info->o_diff_name, info->o_anon_named, info->o_named_anon, info->shared_counter, info->named_shared_counter);
}

int CountSharedPages(VMSNAPSHOT snap)
{
	int ret=0;
	int i;
	for (i=0;i<snap->available_pages;i++)
	{
		if (snap->pages[i].present > 0)
		{
			if (snap->pages[i].reference_count>1)
				ret++;
		}
	}
	return ret;
}

int CountAnonymousVMA(VMSNAPSHOT snap)
{
	int ret;
	int i;

	ret = 0;
	for (i=0;i<snap->vm_region_count;i++)
	{
		if (snap->vms[i].file_name[0]=='/')
			ret++;
	}

	return ret;
}