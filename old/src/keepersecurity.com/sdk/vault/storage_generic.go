package vault

type commonEntityStorage struct {
	genericStorage GenericEntityStorage
}
func (be *commonEntityStorage) Clear() {
	be.genericStorage.Clear()
}
func (be *commonEntityStorage) Delete(uid string) {
	be.genericStorage.Delete(uid)
}

type commonLinkStorage struct {
	genericStorage GenericLinkStorage
}
func (l *commonLinkStorage) Delete(subjectUid string, objectUid string) {
	l.genericStorage.Delete(subjectUid, objectUid)
}
func (l *commonLinkStorage) DeleteObject(objectUid string) {
	l.genericStorage.DeleteObject(objectUid)
}
func (l *commonLinkStorage) DeleteSubject(subjectUid string) {
	l.genericStorage.DeleteSubject(subjectUid)
}
func (l *commonLinkStorage) Clear() {
	l.genericStorage.Clear()
}

/////////////////////////////////
type recordEntityStorage struct {
  commonEntityStorage
}
func  (r *recordEntityStorage) Get(uid string) (data IStorageRecord) {
	var obj =  r.genericStorage.GetEntity(uid)
	if obj != nil {
		data, _ = obj.(IStorageRecord)
	}
	return
}
func  (r *recordEntityStorage) Enumerate(fn func (data IStorageRecord) bool) {
	r.genericStorage.EnumerateEntities(func (obj IUid) bool {
		if r, ok := obj.(IStorageRecord); ok {
			return fn(r)
		}
		return true
	})
}
func  (r *recordEntityStorage) Put(data IStorageRecord) {
	r.genericStorage.PutEntity(data)
}

////////////////////////////////////////
type sharedFolderStorage struct {
  commonEntityStorage
}
func  (sf *sharedFolderStorage) Get(uid string) (data IStorageSharedFolder) {
	var obj =  sf.genericStorage.GetEntity(uid)
	if obj != nil {
		data, _ = obj.(IStorageSharedFolder)
	}
	return
}
func  (sf *sharedFolderStorage) Enumerate(fn func (data IStorageSharedFolder) bool) {
	sf.genericStorage.EnumerateEntities(func (obj IUid) bool {
		if r, ok := obj.(IStorageSharedFolder); ok {
			return fn(r)
		}
		return true
	})
}
func  (sf *sharedFolderStorage) Put(data IStorageSharedFolder) {
	sf.genericStorage.PutEntity(data)
}

//////////////////////////////////
type teamStorage struct {
  commonEntityStorage
}
func  (t *teamStorage) Get(uid string) (data IStorageTeam) {
	var obj =  t.genericStorage.GetEntity(uid)
	if obj != nil {
		data, _ = obj.(IStorageTeam)
	}
	return
}
func  (t *teamStorage) Enumerate(fn func (data IStorageTeam) bool) {
	t.genericStorage.EnumerateEntities(func (obj IUid) bool {
		if r, ok := obj.(IStorageTeam); ok {
			return fn(r)
		}
		return true
	})
}
func  (t *teamStorage) Put(data IStorageTeam) {
	t.genericStorage.PutEntity(data)
}

//////////////////////////////////
type nonSharedDataStorage struct {
  commonEntityStorage
}
func  (nsd *nonSharedDataStorage) Get(uid string) (data IStorageNonSharedData) {
	var obj =  nsd.genericStorage.GetEntity(uid)
	if obj != nil {
		data, _ = obj.(IStorageNonSharedData)
	}
	return
}
func  (nsd *nonSharedDataStorage) Enumerate(fn func (data IStorageNonSharedData) bool) {
	nsd.genericStorage.EnumerateEntities(func (obj IUid) bool {
		if r, ok := obj.(IStorageNonSharedData); ok {
			return fn(r)
		}
		return true
	})
}
func  (nsd *nonSharedDataStorage) Put(data IStorageNonSharedData) {
	nsd.genericStorage.PutEntity(data)
}

//////////////////////////////////
type folderStorage struct {
  commonEntityStorage
}
func  (f *folderStorage) Get(uid string) (data IStorageFolder) {
	var obj =  f.genericStorage.GetEntity(uid)
	if obj != nil {
		data, _ = obj.(IStorageFolder)
	}
	return
}
func  (f *folderStorage) Enumerate(fn func (data IStorageFolder) bool) {
	f.genericStorage.EnumerateEntities(func (obj IUid) bool {
		if r, ok := obj.(IStorageFolder); ok {
			return fn(r)
		}
		return true
	})
}
func  (f *folderStorage) Put(data IStorageFolder) {
	f.genericStorage.PutEntity(data)
}

//////////////////////////////////
type recordKeyLinkStorage struct {
  commonLinkStorage
}
func (l *recordKeyLinkStorage) Put(link IStorageRecordKey) {
	l.genericStorage.PutLink(link)
}
func (l *recordKeyLinkStorage) GetLink(subjectUid string, objectUid string) (rk IStorageRecordKey) {
	if link := l.genericStorage.GetLink(subjectUid, objectUid); link != nil {
		rk, _ = link.(IStorageRecordKey)
	}
	return
}
func (l *recordKeyLinkStorage) GetLinksForSubject(subjectUid string, fn func (IStorageRecordKey) bool) {
	l.genericStorage.GetLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageRecordKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (l *recordKeyLinkStorage) GetLinksForObject(objectUid string, fn func (IStorageRecordKey) bool) {
	l.genericStorage.GetLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageRecordKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (l *recordKeyLinkStorage) GetAllLinks(fn func (IStorageRecordKey) bool) {
	l.genericStorage.GetAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(IStorageRecordKey); ok {
			return fn(rk)
		}
		return true
	})
}

////////////////////////////////////
type sharedFolderKeyStorage struct {
  commonLinkStorage
}
func (sfk *sharedFolderKeyStorage) Put(link IStorageSharedFolderKey) {
	sfk.genericStorage.PutLink(link)
}
func (sfk *sharedFolderKeyStorage) GetLinksForSubject(subjectUid string, fn func (IStorageSharedFolderKey) bool) {
	sfk.genericStorage.GetLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageSharedFolderKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (sfk *sharedFolderKeyStorage) GetLinksForObject(objectUid string, fn func (IStorageSharedFolderKey) bool) {
	sfk.genericStorage.GetLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageSharedFolderKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (sfk *sharedFolderKeyStorage) GetAllLinks(fn func (IStorageSharedFolderKey) bool) {
	sfk.genericStorage.GetAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(IStorageSharedFolderKey); ok {
			return fn(rk)
		}
		return true
	})
}

///////////////////////////////////////
type sharedFolderPermissionStorage struct {
  commonLinkStorage
}
func (sfp *sharedFolderPermissionStorage) Put(link IStorageSharedFolderPermission) {
	sfp.genericStorage.PutLink(link)
}
func (sfp *sharedFolderPermissionStorage) GetLinksForSubject(subjectUid string, fn func (IStorageSharedFolderPermission) bool) {
	sfp.genericStorage.GetLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageSharedFolderPermission); ok {
			return fn(rk)
		}
		return true
	})
}
func (sfp *sharedFolderPermissionStorage) GetLinksForObject(objectUid string, fn func (IStorageSharedFolderPermission) bool) {
	sfp.genericStorage.GetLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageSharedFolderPermission); ok {
			return fn(rk)
		}
		return true
	})
}
func (sfp *sharedFolderPermissionStorage) GetAllLinks(fn func (IStorageSharedFolderPermission) bool) {
	sfp.genericStorage.GetAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(IStorageSharedFolderPermission); ok {
			return fn(rk)
		}
		return true
	})
}

//////////////////////////////////////////
type teamKeyStorage struct {
  commonLinkStorage
}
func (tk *teamKeyStorage) Put(link IStorageTeamKey) {
	tk.genericStorage.PutLink(link)
}
func (tk *teamKeyStorage) GetLinksForSubject(subjectUid string, fn func (IStorageTeamKey) bool) {
	tk.genericStorage.GetLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageTeamKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (tk *teamKeyStorage) GetLinksForObject(objectUid string, fn func (IStorageTeamKey) bool) {
	tk.genericStorage.GetLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageTeamKey); ok {
			return fn(rk)
		}
		return true
	})
}
func (tk *teamKeyStorage) GetAllLinks(fn func (IStorageTeamKey) bool) {
	tk.genericStorage.GetAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(IStorageTeamKey); ok {
			return fn(rk)
		}
		return true
	})
}

//////////////////////////////////////////
type folderRecordStorage struct {
  commonLinkStorage
}
func (fr *folderRecordStorage) Put(link IStorageFolderRecord) {
	fr.genericStorage.PutLink(link)
}
func (fr *folderRecordStorage) GetLinksForSubject(subjectUid string, fn func (IStorageFolderRecord) bool) {
	fr.genericStorage.GetLinksForSubject(subjectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageFolderRecord); ok {
			return fn(rk)
		}
		return true
	})
}
func (fr *folderRecordStorage) GetLinksForObject(objectUid string, fn func (IStorageFolderRecord) bool) {
	fr.genericStorage.GetLinksForObject(objectUid, func(link IUidLink) bool {
		if rk, ok := link.(IStorageFolderRecord); ok {
			return fn(rk)
		}
		return true
	})
}
func (fr *folderRecordStorage) GetAllLinks(fn func (IStorageFolderRecord) bool) {
	fr.genericStorage.GetAllLinks(func(link IUidLink) bool {
		if rk, ok := link.(IStorageFolderRecord); ok {
			return fn(rk)
		}
		return true
	})
}


func NewRecordEntityStorage(storage GenericEntityStorage) IRecordEntityStorage {
	return &recordEntityStorage{
		commonEntityStorage{
			genericStorage: storage,
		},
	}
}
func NewSharedFolderEntityStorage(storage GenericEntityStorage) ISharedFolderEntityStorage {
	return &sharedFolderStorage{
		commonEntityStorage{
			genericStorage: storage,
		},
	}
}
func NewTeamEntityStorage(storage GenericEntityStorage) ITeamEntityStorage {
	return &teamStorage{
		commonEntityStorage{
			genericStorage: storage,
		},
	}
}
func NewNonSharedDataEntityStorage(storage GenericEntityStorage) INonSharedDataEntityStorage {
	return &nonSharedDataStorage{
		commonEntityStorage{
			genericStorage: storage,
		},
	}
}
func NewFolderEntityStorage(storage GenericEntityStorage) IFolderEntityStorage {
	return &folderStorage{
		commonEntityStorage{
			genericStorage: storage,
		},
	}
}
func NewRecordKeyLinkStorage(storage GenericLinkStorage) IRecordKeysStorage {
	return &recordKeyLinkStorage{
		commonLinkStorage{
			genericStorage: storage,
		},
	}
}
func NewSharedFolderKeyLinkStorage(storage GenericLinkStorage) ISharedFolderKeysStorage {
	return &sharedFolderKeyStorage{
		commonLinkStorage{
			genericStorage: storage,
		},
	}
}
func NewSharedFolderPermissionLinkStorage(storage GenericLinkStorage) ISharedFolderPermissionsStorage {
	return &sharedFolderPermissionStorage{
		commonLinkStorage{
			genericStorage: storage,
		},
	}
}
func NewTeamKeyLinkStorage(storage GenericLinkStorage) ITeamKeysStorage {
	return &teamKeyStorage{
		commonLinkStorage{
			genericStorage: storage,
		},
	}
}
func NewFolderRecordLinkStorage(storage GenericLinkStorage) IFolderRecordsStorage {
	return &folderRecordStorage{
		commonLinkStorage{
			genericStorage: storage,
		},
	}
}





