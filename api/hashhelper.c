// hashhelpe functionss

#include "../include/hashhelper.h"
#include <stdio.h>

// Internal helpers
void CountSharedCollisons(const struct PageTableEntryInfo *pte1, const unsigned char *zerohash, const char* filename, struct CollisionInfo *info);
void CountSharingOpsCollisons(const struct PageTableEntryInfo *pte1, const unsigned char *zerohash, const char* filename, struct CollisionInfo *info);


//Create HashMaps
HashMap* CreateHashMap()
{
	HashMap *map;
	map = new HashMap();
	map->hm = new ContentMap();
	map->pm = new PFNMap();
	return map;
}


void ReleaseHashMap(HashMap* map)
{
	if (map!=NULL)
	{
		map->hm->clear();
		map->pm->clear();
		delete map->hm;
		delete map->pm;
		delete map;
	}
}


int AddSnapshotToHashMap(HashMap* map, VMSNAPSHOT snap, CollisionInfo *info)
{
	const unsigned char *zerohash;
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];
	int i;

	if (map==NULL)
		return -1;
	if (snap==NULL)
		return -2;
	if (info==NULL)
		return -3;

	zerohash = GetZeroPageHash(snap->flags);

	for(i=0;i<snap->available_pages;i++)
	{
		if (snap->pages[i].present > 0)
		{
			// Counter
			if (snap->pages[i].reference_count>1)
			{
				// shared page
				info->shared_counter++;
				if (snap->pages[i].inode_no>2)
				{
					// shared page contains an inode
					info->named_shared_counter++;
				}
			}

			pair<ContentMap::iterator, bool> ret;
			ContentPair p;
			p = ContentPair(string(ConvertMD5Hash(snap->pages[i].hash, tmp_buffer)), &snap->pages[i]);

			ret = map->hm->insert(p);
			if (!ret.second)
			{
				//increment internal count
				ret.first->second->reserved++;
				//if (p.second->present >0)
				{
					info->shareable++;
					if (p.second->pfn == ret.first->second->pfn)
					{
						CountSharedCollisons(p.second, zerohash, snap->vms[p.second->present-1].file_name, info);
					}
					else
					{
						// search in PFNMap
						PFNMap::iterator it;
						pair<PFNMap::iterator, bool> ret;
		
						ret = map->pm->insert(PFNPair(p.second->pfn, p.second));
						if (!ret.second)
						{
							// found - so already in map => shared
							CountSharedCollisons(p.second, zerohash, snap->vms[p.second->present-1].file_name, info);						
						}
						else
						{
							/*ContentMap::iterator it3;
								it3 = map->hm->find(p.first);
								if (it3!=map->hm->end())				
								{*/
									CountSharingOpsCollisons(p.second, zerohash, snap->vms[p.second->present-1].file_name, info);
								//}
						}
					}
				}
			}
			else
			{
				info->unshareable++;
			}
		}
	}

	//printf("unshareable: %d\n", info->unshareable);
	//printf("shareable: %d\n", info->shareable);
	//printf("shared: %d\n", info->shared);
	//printf("sharing op: %d\n", info->sharing_op);

	//printf("available: %d\n", snap->available_pages);

	return info->shareable;
}

int MergeHashMaps(HashMap* map1, HashMap *map2, VMSNAPSHOT snap, CollisionInfo *info)
{
	const unsigned char *zerohash;
	if (map1==NULL)
		return -1;
	if (map2==NULL)
		return -2;
	if (info==NULL)
		return -3;

	// find entries of hash2 in hash1
	ContentMap::iterator iter;
	iter = map2->hm->begin();
	
	zerohash = GetZeroPageHash(snap->flags);

	while(iter!=map2->hm->end())
	{
		ContentMap::iterator it;
		pair<ContentMap::iterator, bool> ret;
		
		ret = map1->hm->insert(ContentPair(iter->first, iter->second));
		if (!ret.second)
		{
			it = ret.first;
			// found entry
			if (it->second->present > 0)
			{
				info->shareable++;
				if (it->second->pfn == iter->second->pfn)
					CountSharedCollisons(it->second, zerohash, snap->vms[it->second->present-1].file_name, info);
				else
					CountSharingOpsCollisons(it->second, zerohash, snap->vms[it->second->present-1].file_name, info);				
			}
			
		}
		iter++;
	}

	return info->shareable;
}

int ProbeHashMaps(HashMap* map1, HashMap *map2, VMSNAPSHOT snap, CollisionInfo *info)
{
	const unsigned char *zerohash;
	if (map1==NULL)
		return -1;
	if (map2==NULL)
		return -2;
	if (info==NULL)
		return -3;

	// find entries of hash2 in hash1
	ContentMap::iterator iter;
	iter = map2->hm->begin();
	
	zerohash = GetZeroPageHash(snap->flags);

	while(iter!=map2->hm->end())
	{
		ContentMap::iterator it;
		it = map1->hm->find(iter->first);
		if (it!=map1->hm->end())
		{
			// found entry
			if (it->second->present > 0)
			{
				info->shareable++;
				if (it->second->pfn == iter->second->pfn)
					CountSharedCollisons(it->second, zerohash, snap->vms[it->second->present-1].file_name, info);
				else
					CountSharingOpsCollisons(it->second, zerohash, snap->vms[it->second->present-1].file_name, info);				
			}
			
		}
		iter++;
	}

	return 0;
}

void ClearHashMap(HashMap* map)
{
	if (map!=NULL)
	{
		map->hm->clear();
		map->pm->clear();
	}
}

void CountSharedCollisons(const struct PageTableEntryInfo *pte1, const unsigned char *zerohash, const char* filename, struct CollisionInfo *info)
{

	info->shared++;
	if (CompareHash(pte1->hash, zerohash, 20)==0)
		info->shared_zero++;

	//printf("SH:%s\n", filename);
	switch(filename[0])
	{
	case STACK_MARK:
		info->s_stack++;
		if (IsWriteable(pte1->pte_flags))
			info->s_srw++;
		break;
	case HEAP_MARK:
		info->s_heap++;
		if (IsWriteable(pte1->pte_flags))
			info->s_hrw++;
		break;
	case '/':
		if (pte1->inode_no>=1)
		{
			info->s_named++;
			if (IsWriteable(pte1->pte_flags))
				info->s_nrw++;
		}
		else
		{
			info->s_anon++;
			if (IsWriteable(pte1->pte_flags))
				info->s_arw++;
		}
		break;
	default:
		info->s_named++;
		if (IsWriteable(pte1->pte_flags))
			info->s_nrw++;
		break;
	}
}
void CountSharingOpsCollisons(const struct PageTableEntryInfo *pte1, const unsigned char *zerohash, const char* filename, struct CollisionInfo *info)
{
	info->sharing_op++;
	if (CompareHash(pte1->hash, zerohash, 20)==0)
		info->sharing_zero++;

	//printf("SO:%s\n", filename);
	switch(filename[0])
	{
	case STACK_MARK:
		info->o_stack++;
		if (IsWriteable(pte1->pte_flags))
			info->o_srw++;
		break;
	case HEAP_MARK:
		info->o_heap++;
		if (IsWriteable(pte1->pte_flags))
			info->o_hrw++;
		break;
	case '/':
		if (pte1->inode_no>=1)
		{
			info->o_named++;
			if (IsWriteable(pte1->pte_flags))
				info->o_nrw++;
		}
		else
		{
			info->o_anon++;
			if (IsWriteable(pte1->pte_flags))
				info->o_arw++;
		}
		break;
	default:
		info->o_named++;
		if (IsWriteable(pte1->pte_flags))
			info->o_nrw++;
		break;
	}
}

int TestSnapshotAgainstHashMap(VMSNAPSHOT snap, HashMap* map, HashMap* map2,  CollisionInfo *info, CollisionInfo *info2)
{
	const unsigned char *zerohash;
	char tmp_buffer[MAX_TMP_BUFFER_SIZE];
	int i;

	if (map==NULL)
		return -1;
	if (snap==NULL)
		return -2;
	if (info==NULL)
		return -3;
	int test=0,test2=0;

	PFNMap *newpfnmap = new PFNMap();

	PFNMap::iterator it2;
	pair<PFNMap::iterator, bool> ret;
	pair<PFNMap::iterator, bool> ret2;
	PFNPair pfn;	

	zerohash = GetZeroPageHash(snap->flags);

	for(i=0;i<snap->available_pages;i++)
	{
		if (snap->pages[i].present > 0)
		{
			// Counter
			if (snap->pages[i].reference_count>1)
			{
				// shared page
				info->shared_counter++;
				if (snap->pages[i].inode_no>2)
				{
					// shared page contains an inode
					info->named_shared_counter++;
				}
			}
		//	pair<PFNMap::iterator, bool> ret2;
		//	PFNPair pfn;
		//	pfn = PFNPair(snap->pages[i].pfn,  &snap->pages[i]);
		//	ret2 = newpfnmap->insert(pfn);
			//if (1)//ret2.second)
			//{
				// we have to deal with it
				//pair<ContentMap::iterator, bool> ret;
				//ContentPair p;
				//p = ContentPair(string(ConvertMD5Hash(snap->pages[i].hash, tmp_buffer)), &snap->pages[i]);

				//TODO maybe no add is better
				ContentMap::iterator it;
				it = map->hm->find(string(ConvertMD5Hash(snap->pages[i].hash, tmp_buffer)));
				if (it!=map->hm->end())
				{
					//is in hashmap
					
						
						if (snap->pages[i].pfn == it->second->pfn)
						{
							//TODO check hash integrity
							/*if (CompareMD5Hash(ret2.first->second->hash, snap->pages[i].hash)!=0)
							{
								printf("Changed internal\n");
								//something went wrong
							}*/
							
								
								CountSharedCollisons(&snap->pages[i], zerohash, snap->vms[snap->pages[i].present-1].file_name, info);
								info->shareable++;
							
						}
						else
						{
							// search in PFNMap
							
							//TODO maybe no add is better
			
							it2 = map->pm->find(snap->pages[i].pfn);
							if (it2!=map->pm->end())
							{
								//TODO check hash integretiy
								// found - so already in map => shared
								CountSharedCollisons(&snap->pages[i], zerohash, snap->vms[snap->pages[i].present-1].file_name, info);						
								info->shareable++;
							}
							else
							{
								/*ContentMap::iterator it3;
								it3 = map2->hm->find(string(ConvertMD5Hash(snap->pages[i].hash, tmp_buffer)));
								if (it3==map2->hm->end())				
								{*/
								pfn = PFNPair(snap->pages[i].pfn,  &snap->pages[i]);
								ret2 = newpfnmap->insert(pfn);
								if (ret2.second)
								{
									CountSharingOpsCollisons(&snap->pages[i], zerohash, snap->vms[snap->pages[i].present-1].file_name, info);
									info->shareable++;
								}
								else
								{
									CountSharedCollisons(&snap->pages[i], zerohash, snap->vms[snap->pages[i].present-1].file_name, info);						
									info->shareable++;
								}
							}
						}
					
				}	
				else
				{
					//not found
					test++;

					pair<ContentMap::iterator, bool> ret;
					ContentPair p;
					p = ContentPair(string(ConvertMD5Hash(snap->pages[i].hash, tmp_buffer)), &snap->pages[i]);

					ret = map2->hm->insert(p);
					if (!ret.second)
					{
						//increment internal count
						ret.first->second->reserved++;
						//if (p.second->present >0)
				
							info2->shareable++;
							if (p.second->pfn == ret.first->second->pfn)
							{
								CountSharedCollisons(p.second, zerohash, snap->vms[p.second->present-1].file_name, info2);
							}
							else
							{
								// search in PFNMap
								PFNMap::iterator it;
								pair<PFNMap::iterator, bool> ret;
		
								ret = map2->pm->insert(PFNPair(p.second->pfn, p.second));
								if (!ret.second)
								{
									// found - so already in map => shared
									CountSharedCollisons(p.second, zerohash, snap->vms[p.second->present-1].file_name, info2);						
								}
								else
								{
									CountSharingOpsCollisons(p.second, zerohash, snap->vms[p.second->present-1].file_name, info2);
								}
							}
				
				
					}
					else
					{
						info->unshareable++;
					}
				}
			//}
			/*else
			{
				//already processed
				if (CompareMD5Hash(ret2.first->second->hash, snap->pages[i].hash)!=0)
				{
					printf("Changed internal\n");
					//something went wrong
				}
				//printf("already processed\n");
				test2++;
			}*/	
			
		}
	}

	//printf("%d %d\n",test,test2);
	newpfnmap->clear();
	delete newpfnmap;

	return info->shareable;
}

int HashMapAgainstHashMap(HashMap *map1, HashMap *map2)
{
	int ret=0;
	int ret2=0;
	ContentMap::iterator iter;
	iter = map2->hm->begin();

	while(iter!=map2->hm->end())
	{
		ContentMap::iterator it;
		it = map1->hm->find(iter->first);
		if (it==map1->hm->end())
		{
			
			ret++;
		}
		iter++;
	}
	
	iter = map1->hm->begin();

	while(iter!=map1->hm->end())
	{
		ContentMap::iterator it;
		it = map2->hm->find(iter->first);
		if (it==map2->hm->end())
		{
			
			ret2++;
		}
		iter++;
	}

	printf("%d %d %d\n", ret, ret2, ret2-ret);
	return ret;
}