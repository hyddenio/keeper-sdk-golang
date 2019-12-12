package sdk

type inMemoryEntityStorage struct {
	storage map[string]IUid
}
func (es *inMemoryEntityStorage) Clear() {
	es.storage = nil
}
func (es *inMemoryEntityStorage) Delete(uid string) {
	if es.storage != nil {
		delete(es.storage, uid)
	}
}
func  (es *inMemoryEntityStorage) get(uid string) (entity IUid) {
	if es.storage != nil {
		entity = es.storage[uid]
	}
	return
}
func  (es *inMemoryEntityStorage) put(data IUid) {
	if es.storage == nil {
		es.storage = make(map[string]IUid, 0)
	}
	es.storage[data.Uid()] = data
}
func  (es *inMemoryEntityStorage) enumerate(fn func (data IUid) bool) {
	if es != nil {
		for _, v := range es.storage {
			if !fn(v) {
				break
			}
		}
	}
}

type inMemoryPredicateStorage struct {
	storage map[string]map[string]IUidLink
}
func (ps *inMemoryPredicateStorage) DeleteLink(link IUidLink) {
	if ps.storage != nil {
		objects := ps.storage[link.SubjectUid()]
		if objects != nil {
			delete(objects, link.ObjectUid())
			if len(objects) == 0 {
				delete(ps.storage, link.SubjectUid())
			}
		}
	}
}
func (ps *inMemoryPredicateStorage) Delete(subjectUid string, objectUid string) {
	if ps.storage != nil {
		ps.DeleteLink(&UidLink{
			subjectUid: subjectUid,
			objectUid:  objectUid,
		})
	}
}
func (ps *inMemoryPredicateStorage) DeleteObject(objectUid string) {
	if ps.storage != nil {
		for subjectUid, objects := range ps.storage {
			delete(objects, objectUid)
			if len(objects) == 0 {
				delete(ps.storage, subjectUid)
			}
		}
	}
}
func (ps *inMemoryPredicateStorage) DeleteSubject(subjectUid string) {
	if ps.storage != nil {
		delete(ps.storage, subjectUid)
	}
}
func (ps *inMemoryPredicateStorage) Clear() {
	ps.storage = nil
}

func (ps *inMemoryPredicateStorage) put(link IUidLink) {
	var objects map[string]IUidLink
	if ps.storage == nil {
		ps.storage = make(map[string]map[string]IUidLink)
	} else {
		objects = ps.storage[link.SubjectUid()]
	}
	if objects == nil {
		objects = make(map[string]IUidLink)
		ps.storage[link.SubjectUid()] = objects
	}
	objects[link.ObjectUid()] = link
}
func (ps *inMemoryPredicateStorage) getLink(subjectUid string, objectUid string) (link IUidLink) {
	if ps.storage != nil {
		objects := ps.storage[subjectUid]
		if objects != nil {
			link = objects[objectUid]
		}
	}
	return
}
func (ps *inMemoryPredicateStorage) getLinksForSubject(subjectUid string, fn func (IUidLink) bool) {
	if ps.storage != nil {
		objects := ps.storage[subjectUid]
		for _, obj := range objects {
			if !fn(obj) {
				return
			}
		}
	}
}
func (ps *inMemoryPredicateStorage) getLinksForObject(objectUid string, fn func (IUidLink) bool) {
	if ps.storage != nil {
		for _, objects := range ps.storage {
			if obj := objects[objectUid]; obj != nil {
				if !fn(obj) {
					return
				}
			}
		}
	}
}
func (ps *inMemoryPredicateStorage) getAllLinks(fn func (IUidLink) bool) {
	if ps.storage != nil {
		for _, objects := range ps.storage {
			for _, obj := range objects {
				if !fn(obj) {
					return
				}
			}
		}
	}
}


type inMemoryRecordStorage struct {
	inMemoryEntityStorage
}
func  (entity *inMemoryRecordStorage) Get(uid string) (data StorageRecord) {
	var obj =  entity.inMemoryEntityStorage.get(uid)
	if obj != nil {
		data, _ = obj.(StorageRecord)
	}
	return
}
func  (entity *inMemoryRecordStorage) Enumerate(fn func (data StorageRecord) bool) {
	entity.inMemoryEntityStorage.enumerate(func (obj IUid) bool {
		if r, ok := obj.(StorageRecord); ok {
			return fn(r)
		}
		return true
	})
}
func  (entity *inMemoryRecordStorage) Put(data StorageRecord) {
	entity.inMemoryEntityStorage.put(data)
}

type inMemoryNonSharedDataStorage struct {
	inMemoryEntityStorage
}
func  (entity *inMemoryNonSharedDataStorage) Get(uid string) (data StorageNonSharedData) {
	var obj =  entity.inMemoryEntityStorage.get(uid)
	if obj != nil {
		data, _ = obj.(StorageNonSharedData)
	}
	return
}
func  (entity *inMemoryNonSharedDataStorage) Enumerate(fn func (data StorageNonSharedData) bool) {
	entity.inMemoryEntityStorage.enumerate(func (obj IUid) bool {
		if r, ok := obj.(StorageNonSharedData); ok {
			return fn(r)
		}
		return true
	})
}
func  (entity *inMemoryNonSharedDataStorage) Put(data StorageNonSharedData) {
	entity.inMemoryEntityStorage.put(data)
}

type inMemorySharedFolderStorage struct {
	inMemoryEntityStorage
}
func  (entity *inMemorySharedFolderStorage) Get(uid string) (data StorageSharedFolder) {
	var obj =  entity.inMemoryEntityStorage.get(uid)
	if obj != nil {
		data, _ = obj.(StorageSharedFolder)
	}
	return
}
func  (entity *inMemorySharedFolderStorage) Enumerate(fn func (data StorageSharedFolder) bool) {
	entity.inMemoryEntityStorage.enumerate(func (obj IUid) bool {
		if r, ok := obj.(StorageSharedFolder); ok {
			return fn(r)
		}
		return true
	})
}
func  (entity *inMemorySharedFolderStorage) Put(data StorageSharedFolder) {
	entity.inMemoryEntityStorage.put(data)
}

type inMemoryTeamStorage struct {
	inMemoryEntityStorage
}
func  (entity *inMemoryTeamStorage) Get(uid string) (data StorageTeam) {
	var obj =  entity.inMemoryEntityStorage.get(uid)
	if obj != nil {
		data, _ = obj.(StorageTeam)
	}
	return
}
func  (entity *inMemoryTeamStorage) Enumerate(fn func (data StorageTeam) bool) {
	entity.inMemoryEntityStorage.enumerate(func (obj IUid) bool {
		if r, ok := obj.(StorageTeam); ok {
			return fn(r)
		}
		return true
	})
}
func  (entity *inMemoryTeamStorage) Put(data StorageTeam) {
	entity.inMemoryEntityStorage.put(data)
}

type inMemoryFolderStorage struct {
	inMemoryEntityStorage
}
func  (entity *inMemoryFolderStorage) Get(uid string) (data StorageFolder) {
	var obj =  entity.inMemoryEntityStorage.get(uid)
	if obj != nil {
		data, _ = obj.(StorageFolder)
	}
	return
}
func  (entity *inMemoryFolderStorage) Enumerate(fn func (data StorageFolder) bool) {
	entity.inMemoryEntityStorage.enumerate(func (obj IUid) bool {
		if r, ok := obj.(StorageFolder); ok {
			return fn(r)
		}
		return true
	})
}
func  (entity *inMemoryFolderStorage) Put(data StorageFolder) {
	entity.inMemoryEntityStorage.put(data)
}


type inMemoryRecordKeyStorage struct {
	inMemoryPredicateStorage
}
func (predicate *inMemoryRecordKeyStorage) Put(link StorageRecordKey) {
	predicate.inMemoryPredicateStorage.put(link)
}
func (predicate *inMemoryRecordKeyStorage) GetLink(subjectUid string, objectUid string) (rk StorageRecordKey) {
	if link := predicate.inMemoryPredicateStorage.getLink(subjectUid, objectUid); link != nil {
		rk, _ = link.(StorageRecordKey)
	}
	return
}
func (predicate *inMemoryRecordKeyStorage) GetLinksForSubject(subjectUid string, fn func (StorageRecordKey) bool) {
	predicate.inMemoryPredicateStorage.getLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageRecordKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemoryRecordKeyStorage) GetLinksForObject(objectUid string, fn func (StorageRecordKey) bool) {
	predicate.inMemoryPredicateStorage.getLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageRecordKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemoryRecordKeyStorage) GetAllLinks(fn func (StorageRecordKey) bool) {
	predicate.inMemoryPredicateStorage.getAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(StorageRecordKey); ok {
			return fn(rk)
		}
		return true
	})
}

type inMemorySharedFolderKeyStorage struct {
	inMemoryPredicateStorage
}
func (predicate *inMemorySharedFolderKeyStorage) Put(link StorageSharedFolderKey) {
	predicate.inMemoryPredicateStorage.put(link)
}
func (predicate *inMemorySharedFolderKeyStorage) GetLinksForSubject(subjectUid string, fn func (StorageSharedFolderKey) bool) {
	predicate.inMemoryPredicateStorage.getLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageSharedFolderKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemorySharedFolderKeyStorage) GetLinksForObject(objectUid string, fn func (StorageSharedFolderKey) bool) {
	predicate.inMemoryPredicateStorage.getLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageSharedFolderKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemorySharedFolderKeyStorage) GetAllLinks(fn func (StorageSharedFolderKey) bool) {
	predicate.inMemoryPredicateStorage.getAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(StorageSharedFolderKey); ok {
			return fn(rk)
		}
		return true
	})
}

type inMemorySharedFolderPermissionStorage struct {
	inMemoryPredicateStorage
}
func (predicate *inMemorySharedFolderPermissionStorage) Put(link StorageSharedFolderPermission) {
	predicate.inMemoryPredicateStorage.put(link)
}
func (predicate *inMemorySharedFolderPermissionStorage) GetLinksForSubject(subjectUid string, fn func (StorageSharedFolderPermission) bool) {
	predicate.inMemoryPredicateStorage.getLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageSharedFolderPermission); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemorySharedFolderPermissionStorage) GetLinksForObject(objectUid string, fn func (StorageSharedFolderPermission) bool) {
	predicate.inMemoryPredicateStorage.getLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageSharedFolderPermission); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemorySharedFolderPermissionStorage) GetAllLinks(fn func (StorageSharedFolderPermission) bool) {
	predicate.inMemoryPredicateStorage.getAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(StorageSharedFolderPermission); ok {
			return fn(rk)
		}
		return true
	})
}

type inMemoryTeamKeyStorage struct {
	inMemoryPredicateStorage
}
func (predicate *inMemoryTeamKeyStorage) Put(link StorageTeamKey) {
	predicate.inMemoryPredicateStorage.put(link)
}
func (predicate *inMemoryTeamKeyStorage) GetLinksForSubject(subjectUid string, fn func (StorageTeamKey) bool) {
	predicate.inMemoryPredicateStorage.getLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageTeamKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemoryTeamKeyStorage) GetLinksForObject(objectUid string, fn func (StorageTeamKey) bool) {
	predicate.inMemoryPredicateStorage.getLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageTeamKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemoryTeamKeyStorage) GetAllLinks(fn func (StorageTeamKey) bool) {
	predicate.inMemoryPredicateStorage.getAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(StorageTeamKey); ok {
			return fn(rk)
		}
		return true
	})
}

type inMemoryFolderRecordStorage struct {
	inMemoryPredicateStorage
}
func (predicate *inMemoryFolderRecordStorage) Put(link StorageFolderRecord) {
	predicate.inMemoryPredicateStorage.put(link)
}
func (predicate *inMemoryFolderRecordStorage) GetLinksForSubject(subjectUid string, fn func (StorageFolderRecord) bool) {
	predicate.inMemoryPredicateStorage.getLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageFolderRecord); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemoryFolderRecordStorage) GetLinksForObject(objectUid string, fn func (StorageFolderRecord) bool) {
	predicate.inMemoryPredicateStorage.getLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(StorageFolderRecord); ok {
			return fn(rk)
		}
		return true
	})
}
func (predicate *inMemoryFolderRecordStorage) GetAllLinks(fn func (StorageFolderRecord) bool) {
	predicate.inMemoryPredicateStorage.getAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(StorageFolderRecord); ok {
			return fn(rk)
		}
		return true
	})
}


type inMemoryKeeperStorage struct {
	revision int64

	records *inMemoryRecordStorage
	sharedFolders *inMemorySharedFolderStorage
	teams *inMemoryTeamStorage
	nonSharedData *inMemoryNonSharedDataStorage
	folders *inMemoryFolderStorage

	recordKeys *inMemoryRecordKeyStorage
	sharedFolderKeys *inMemorySharedFolderKeyStorage
	sharedFolderPermissions *inMemorySharedFolderPermissionStorage
	teamKeys *inMemoryTeamKeyStorage
	folderRecords *inMemoryFolderRecordStorage
}
func (storage *inMemoryKeeperStorage) PersonalScopeUid() string {
	return "PersonalScopeUid"
}
func (storage *inMemoryKeeperStorage) Revision() int64 {
	return storage.revision
}
func (storage *inMemoryKeeperStorage) SetRevision(value int64) {
	storage.revision = value
}

func (storage *inMemoryKeeperStorage) Records() RecordEntityStorage {
	return storage.records
}
func (storage *inMemoryKeeperStorage) NonSharedData() NonSharedDataEntityStorage {
	return storage.nonSharedData
}
func (storage *inMemoryKeeperStorage) SharedFolders() SharedFolderEntityStorage {
	return storage.sharedFolders
}
func (storage *inMemoryKeeperStorage) Teams() TeamEntityStorage {
	return storage.teams
}
func (storage *inMemoryKeeperStorage) Folders() FolderEntityStorage {
	return storage.folders
}

func (storage *inMemoryKeeperStorage) RecordKeys() RecordKeysStorage {
	return storage.recordKeys
}
func (storage *inMemoryKeeperStorage) SharedFolderKeys() SharedFolderKeysStorage {
	return storage.sharedFolderKeys
}

func (storage *inMemoryKeeperStorage) SharedFolderPermissions() SharedFolderPermissionsStorage {
	return storage.sharedFolderPermissions
}

func (storage *inMemoryKeeperStorage) TeamKeys() TeamKeysStorage {
	return storage.teamKeys
}

func (storage *inMemoryKeeperStorage) FolderRecords() FolderRecordsStorage {
	return storage.folderRecords
}
func (storage *inMemoryKeeperStorage) Clear() {
	storage.revision = 0
	storage.records = new(inMemoryRecordStorage)
	storage.sharedFolders = new(inMemorySharedFolderStorage)
	storage.teams = new(inMemoryTeamStorage)
	storage.folders = new(inMemoryFolderStorage)
	storage.recordKeys = new(inMemoryRecordKeyStorage)
	storage.sharedFolderKeys = new(inMemorySharedFolderKeyStorage)
	storage.sharedFolderPermissions = new(inMemorySharedFolderPermissionStorage)
	storage.teamKeys = new(inMemoryTeamKeyStorage)
	storage.folderRecords = new(inMemoryFolderRecordStorage)
}