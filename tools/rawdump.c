#include "../include/vmsnapshot.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, const char* argv[])
{
	VMSNAPSHOT snap;
	int i=0,j;
	int count;
	int index,loop;
	struct InputParams result;
	VMSNAPSHOT *snaps;


	index = ProcessInputParams(argc, argv, &result);
	
	if (index+1 > argc)
	{
		printf("USGAE: <options> pid1:flags pid2:flags ... pidN:flags\n");
		PrintOptionsHelp();
		return 0;
	}

	for (loop=0;loop<result.snapshotcount;loop++)
	{
		for (i=index;i<argc;i++)
		{
			if (argv[i][0] == '*')
			{

				snaps = TakeSnapshots(atoi(&argv[i][2]), &count);
				printf("%d - %p\n", count, snaps);
				if (snaps!=NULL)
				{
					for (j=0;j<count;j++)
					{
						if (snaps[j]!=NULL)
						{
							printf("%p - %d\n",snaps[j],snaps[j]->pid);
						
							PrintSnapshotInfoEx(snaps[j]);
							SaveSnapshot(snaps[j]);
							ReleaseSnapshot(snaps[j]);
						}
					}

					free(snaps);
				}
			}
			else
			{
				snap = TakeSnapshotEx(argv[i], strlen(argv[i]));
				if (snap!=NULL)
				{
					SaveSnapshot(snap);
					if (result.csv)
						PrintSnapshotInfo(snap);
					else
						PrintSnapshotInfoEx(snap);
					ReleaseSnapshot(snap);
				}
				else
				{
					printf("Snapshot could not be taken.\n");
					return -1;
				}
			}
			sleep(result.sleeptime);
		}
	}

	return 0;
}
