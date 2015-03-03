
static const char *VMFLAGSTOCHAR[] = {
	"R", // 1 Read
	"W", // 2 Write
	"X", // 4 Execute
	"S", // 8 Shared
	"r", // 1 may read
	"w", // 2 may write
	"x", // 4 may execute
	"s", // 8 may share
	"G", // 1 grows down
	"p", // 2 no huge page
	"F", // 4 pfn map
	"N", // 8 deny write
	"E", // 1 executable
	"L", // 2 locked
	"I", // 4 IO mapped page
	"+", // 8 sequential read
	"?", // 1 random read
	"C", // 2 don't copy
	"!", // 4 don't expand
	"|", // 8 reserved
	"A", // 1 account
	"#", // 2 no reserve
	"H", // 4 huge tlb
	"~", // 8 non linear
	"h", // 1 huge page
	"i", // 2 insert page
	"D", // 4 always dump
	"*", // 8 can non linear
	"m", // 1 mixed map
	"Y", // 2 sao
    "@", // 4 pfn at mmpa
    "M" // 8 mergable
};

static const char *VMFLAGSTOSTRING[] = {
	"VM_READ",
	"VM_WRITE",
	"VM_EXEC",
	"VM_SHARED",
	"VM_MAYREAD",
	"VM_MAYWRITE",
	"VM_MAYEXEC",
	"VM_MAYSHARE",
	"VM_GROWSDOWN",
	"VM_NOHUGEPAGE",
	"VM_PFNMAP",
	"VM_DENYWRITE",
	"VM_EXECUTEABLE",
	"VM_LOCKED",
	"VM_IO",
	"VM_SEQ_READ",
	"VM_RAND_READ",
	"VM_DONTCOPY",
	"VM_DONTEXPAND",
	"VM_RESERVED",
	"VM_ACCOUNT",
	"VM_NORESERVE",
	"VM_HUGETLB",
	"VM_NONLINEAR",
	"VM_HUGEPAGE",
	"VM_INSERTPAGE",
	"VM_ALAWYSDUMP",
	"VM_CAN_NONLINEAR",
	"VM_MIXEDMAP",
	"VM_SAO",
	"VM_PFN_AT_MMAP",
	"VM_MERGEABLE"
};

static const char *PTEFLAGSTOCHAR[] =
{
	"Pr", // 1 Present
	"RW", // 2 Writeable - Write implies read
	"Us", // 4 Userspace accessible
	"PW", // 8 Page writethrough
	"PC", // 1 Page cache disabled
	"Ac", // 2 Accessed
	"Dr", // 4 Dirty - written
	"PS", // 8 PSE
	"PT", // 1 PAT
	"Gl", // 2 Global
	"Un", // 4 Unused1
	"IO", // 8 IO mapped
	"Hd", // 1 Hidden
	"PL", // 2 PAT Large
	"NX", // 63 No Execution
};

static const char *PTEFLAGSTOSTRING[] =
{
	"Present",
	"ReadWrite",
	"Userspace",
	"PageWriteThrough",
	"PageCacheDisabled",
	"Accessed",
	"Dirty",
	"PSE",
	"PAT",
	"Global",
	"Unused1",
	"IO Map",
	"Hidden",
	"PAT Large",
	"NX"

};

static const char* PAGEFLAGSTOCHAR[] =
{
	"L",
	"e",
	"R",
	"u",
	"d",
	"l",
	"A",
	"s",
	"o",
	"a",
	"r",
	"p",
	"2",
	"w",
	"c", // might be 2 entries PG_head and PG_tail
	"s",
	"m",
	"C",
	"w",
	"u",
	"M", // config MMU
	"n", // ARCH uses uncached
	"P",
	"K" // TRANSPARENT HUGE
	
};


static const char* PAGEFLAGSTOSTRING[] =
{
	"PG_locked",
	"PG_error",
	"PG_referenced",
	"PG_uptodate",
	"PG_dirty",
	"PG_lru",
	"PG_active",
	"PG_slab",
	"PG_owner_priv1",
	"PG_arch_1",
	"PG_reserved",
	"PG_private",
	"PG_private_2",
	"PG_writeback",
	"PG_compoud", // might be 2 entries PG_head and PG_tail
	"PG_swapcache",
	"PG_mappedtodisk",
	"PG_reclaim",
	"PG_swapbacked",
	"PG_unevictable",
	"PG_mlocked", // config MMU
	"PG_uncached", // ARCH uses uncached
	"PG_hwpoisend",
	"PG_compoud_lock" // TRANSPARENT HUGE
	
};

const char* ZEROPAGEHASHES[] = {
	"\x62\x0f\x0b\x67\xa9\x1f\x7f\x74\x15\x1b\xc5\xbe\x74\x5b\x71\x10\x00\x00\x00\x00", //MD5
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", //CRC32
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", //CRC32EX
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", //Simple Pattern
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", //SuperFastHash
	"\x1c\xea\xf7\x3d\xf4\x0e\x53\x1d\xf3\xbf\xb2\x6b\x4f\xb7\xcd\x95\xfb\x7b\xff\x1d" //SHA1


};