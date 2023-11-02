package vault

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
func  (es *inMemoryEntityStorage) GetEntity(uid string) (entity IUid) {
	if es.storage != nil {
		entity = es.storage[uid]
	}
	return
}
func  (es *inMemoryEntityStorage) PutEntity(data IUid) {
	if es.storage == nil {
		es.storage = make(map[string]IUid, 0)
	}
	es.storage[data.Uid()] = data
}
func  (es *inMemoryEntityStorage) EnumerateEntities(fn func (data IUid) bool) {
	if es != nil {
		for _, v := range es.storage {
			if !fn(v) {
				break
			}
		}
	}
}

type inMemoryLinkStorage struct {
	storage map[string]map[string]IUidLink
}
func (ps *inMemoryLinkStorage) Delete(subjectUid string, objectUid string) {
	if ps.storage != nil {
		objects := ps.storage[subjectUid]
		if objects != nil {
			delete(objects, objectUid)
			if len(objects) == 0 {
				delete(ps.storage, subjectUid)
			}
		}
	}
}
func (ps *inMemoryLinkStorage) DeleteObject(objectUid string) {
	if ps.storage != nil {
		for subjectUid, objects := range ps.storage {
			delete(objects, objectUid)
			if len(objects) == 0 {
				delete(ps.storage, subjectUid)
			}
		}
	}
}
func (ps *inMemoryLinkStorage) DeleteSubject(subjectUid string) {
	if ps.storage != nil {
		delete(ps.storage, subjectUid)
	}
}
func (ps *inMemoryLinkStorage) Clear() {
	ps.storage = nil
}

func (ps *inMemoryLinkStorage) PutLink(link IUidLink) {
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
func (ps *inMemoryLinkStorage) GetLink(subjectUid string, objectUid string) (link IUidLink) {
	if ps.storage != nil {
		objects := ps.storage[subjectUid]
		if objects != nil {
			link = objects[objectUid]
		}
	}
	return
}
func (ps *inMemoryLinkStorage) GetLinksForSubject(subjectUid string, fn func (IUidLink) bool) {
	if ps.storage != nil {
		objects := ps.storage[subjectUid]
		for _, obj := range objects {
			if !fn(obj) {
				return
			}
		}
	}
}
func (ps *inMemoryLinkStorage) GetLinksForObject(objectUid string, fn func (IUidLink) bool) {
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
func (ps *inMemoryLinkStorage) GetAllLinks(fn func (IUidLink) bool) {
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

type keeperStorage struct {
	revision int64

	records       IRecordEntityStorage
	sharedFolders ISharedFolderEntityStorage
	teams         ITeamEntityStorage
	nonSharedData INonSharedDataEntityStorage
	folders       IFolderEntityStorage

	recordKeys              IRecordKeysStorage
	sharedFolderKeys        ISharedFolderKeysStorage
	sharedFolderPermissions ISharedFolderPermissionsStorage
	teamKeys                ITeamKeysStorage
	folderRecords           IFolderRecordsStorage
}
func (storage *keeperStorage) PersonalScopeUid() string {
	return "PersonalScopeUid"
}
func (storage *keeperStorage) Revision() int64 {
	return storage.revision
}
func (storage *keeperStorage) SetRevision(value int64) {
	storage.revision = value
}

func (storage *keeperStorage) Records() IRecordEntityStorage {
	return storage.records
}
func (storage *keeperStorage) NonSharedData() INonSharedDataEntityStorage {
	return storage.nonSharedData
}
func (storage *keeperStorage) SharedFolders() ISharedFolderEntityStorage {
	return storage.sharedFolders
}
func (storage *keeperStorage) Teams() ITeamEntityStorage {
	return storage.teams
}
func (storage *keeperStorage) Folders() IFolderEntityStorage {
	return storage.folders
}

func (storage *keeperStorage) RecordKeys() IRecordKeysStorage {
	return storage.recordKeys
}
func (storage *keeperStorage) SharedFolderKeys() ISharedFolderKeysStorage {
	return storage.sharedFolderKeys
}

func (storage *keeperStorage) SharedFolderPermissions() ISharedFolderPermissionsStorage {
	return storage.sharedFolderPermissions
}

func (storage *keeperStorage) TeamKeys() ITeamKeysStorage {
	return storage.teamKeys
}

func (storage *keeperStorage) FolderRecords() IFolderRecordsStorage {
	return storage.folderRecords
}
func (storage *keeperStorage) Clear() {
	storage.revision = 0
	storage.records.Clear()
	storage.sharedFolders.Clear()
	storage.teams.Clear()
	storage.nonSharedData.Clear()
	storage.recordKeys.Clear()
	storage.sharedFolderKeys.Clear()
	storage.sharedFolderPermissions.Clear()
	storage.teamKeys.Clear()
	storage.folders.Clear()
	storage.folderRecords.Clear()
}

func NewInMemoryVaultStorage() IVaultStorage {
	var storage = &keeperStorage{
		revision:                0,
		records:                 NewRecordEntityStorage(new(inMemoryEntityStorage)),
		sharedFolders:           NewSharedFolderEntityStorage(new(inMemoryEntityStorage)),
		teams:                   NewTeamEntityStorage(new(inMemoryEntityStorage)),
		nonSharedData:           NewNonSharedDataEntityStorage(new(inMemoryEntityStorage)),
		recordKeys:              NewRecordKeyLinkStorage(new(inMemoryLinkStorage)),
		sharedFolderKeys:        NewSharedFolderKeyLinkStorage(new(inMemoryLinkStorage)),
		sharedFolderPermissions: NewSharedFolderPermissionLinkStorage(new(inMemoryLinkStorage)),
		teamKeys:                NewTeamKeyLinkStorage(new(inMemoryLinkStorage)),
		folders:                 NewFolderEntityStorage(new(inMemoryEntityStorage)),
		folderRecords:           NewFolderRecordLinkStorage(new(inMemoryLinkStorage)),
	}
	return storage
}
