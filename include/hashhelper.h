// hash helper functions go here

#include "vmsnapshot.h"

#include <string>
#include <iostream>

#ifndef _DEBUG_ERROR
#include <tr1/unordered_map>
#else
#include <unordered_map>
#endif

using namespace std;
using namespace std::tr1;

// Create Hashmaps

typedef pair<string, struct PageTableEntryInfo*> ContentPair;
typedef unordered_map<string, struct PageTableEntryInfo*> ContentMap;

typedef pair<unsigned long, struct PageTableEntryInfo*> PFNPair;
typedef unordered_map<unsigned long, struct PageTableEntryInfo*> PFNMap;

typedef struct Maps
{
	ContentMap* hm;
	PFNMap * pm;
} HashMap;

HashMap* CreateHashMap();


void ReleaseHashMap(HashMap* map);


int AddSnapshotToHashMap(HashMap* map, VMSNAPSHOT snap, CollisionInfo *info);

int MergeHashMaps(HashMap* map1, HashMap *map2, VMSNAPSHOT snap, CollisionInfo *info);

int ProbeHashMaps(HashMap* map1, HashMap *map2, VMSNAPSHOT snap, CollisionInfo *info);

void ClearHashMap(HashMap* map);

int TestSnapshotAgainstHashMap(VMSNAPSHOT snap, HashMap* map, HashMap* map2,  CollisionInfo *info, CollisionInfo *info2);

int HashMapAgainstHashMap(HashMap *map1, HashMap *map2);