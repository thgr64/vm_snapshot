# vm_snapshot

Allows to hash the content of a virtual address space
 and dump page-table information on x86

The kernel module should run on Linux 2.6.3x and newer (3.13 tested).

./rawdump pid:flags
(pid in decimal, flags in hexdecimal)

pid = 0, all frames in the system are hashed
flags: combination of the following
ONLY_PRESENT_PAGES	1

and one of the following hashes (default hash is MD5)
HASH_CRC32		16

HASH_CRC32_EX		32
HASH_SHA1		128
HASH_SUPERFAST		256


Example:
./rawdump 0:1 
(hashes all physical frames and saves it to a file starting with 0-)

./rawdump 1234:11
(hashes all present pages of task 1234 with CRC32 and stores it to file 1234-)

./printrawdump filename
(opens a saved dump and outputs it in human-readable form)