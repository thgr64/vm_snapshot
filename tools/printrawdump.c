#include "../include/vmsnapshot.h"

#include <stdio.h>

int main(int argc, const char* argv[])
{
	VMSNAPSHOT snap;
	if (argc > 1)
	{
		printf("Loading snapshot %s ...\n", argv[1]);
		snap = LoadSnapshot(argv[1]);
		if (snap==NULL)
		{
			printf("Could not load Snapshot %s\n", argv[1]);
			return -1;
		}
		if (argc > 2)
		{
			if (argv[2][0] == 'v')
				PrintVMA(snap, 0, snap->vm_region_count);
			else if(argv[2][0] == 'p')
				PrintPages(snap, 0, snap->available_pages);
		}
		else
			PrintSnapshot(snap);

		//PrintVMA(snap, 0, snap->vm_region_count);
		//PrintSnapshotInfoEx(snap);
		//PrintVMAandPages(snap, 0, 4);
		//PrintPages(snap, 10, 20);
		ReleaseSnapshot(snap);
	}
	else
	{
		printf("This program shows raw snapshots from disk in a human readable form\n");
		printf("USAGE: filename flags\n");
		printf("Flags:\n");
		printf("v\tVirtual Memory Information only\n");
		printf("p\tAll available pages\n");
	}
	return 0;
}
