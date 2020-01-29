package sdk

import "encoding/json"

type rebuildTask struct {
	isFullSync bool
	records set
	sharedFolders set
}
func (t *rebuildTask) addSharedFolder(uid string) {
	if t.sharedFolders == nil {
		t.sharedFolders = make(set)
	}
	if !t.isFullSync {
		t.sharedFolders[uid] = empty
	}
}
func (t *rebuildTask) addRecord(uid string) {
	if t.records == nil {
		t.records = make(set)
	}
	if !t.isFullSync {
		t.records[uid] = empty
	}
}

type VaultData interface {
	VaultStorage() VaultStorage
	ClientKey() []byte

	RootFolder() *Folder

	GetRecord(uid string) *PasswordRecord
	GetAllRecords(func (*PasswordRecord) bool)
	RecordCount() int
	GetSharedFolder(uid string) *SharedFolder
	GetAllSharedFolders(func (*SharedFolder) bool)
	SharedFolderCount() int
	GetTeam(uid string) *EnterpriseTeam
	GetAllTeams(func (*EnterpriseTeam) bool)
	TeamCount() int
	GetFolder(uid string) *Folder
	GetAllFolders(func (*Folder) bool)

	rebuildData(changes *rebuildTask)
	buildFolders()
}


type vaultData struct {
	storage    VaultStorage
	clientKey  []byte
	rootFolder *Folder

	records map[string]*PasswordRecord
	sharedFolders map[string]*SharedFolder
	teams map[string]*EnterpriseTeam
	folders map[string]*Folder
}
func NewVaultData(clientKey []byte, storage VaultStorage) VaultData {
	return &vaultData{
		rootFolder: &Folder{
			FolderUid:       "",
			FolderType:      "user_folder",
			Name:            "My Vault",
			ParentUid:       "",
			SharedFolderUid: "",
			subfolders:      make(map[string]struct{}),
			records:         make(map[string]struct{}),
		},
		storage:       storage,
		clientKey:     clientKey,
		records:       make(map[string]*PasswordRecord, 0),
		sharedFolders: make(map[string]*SharedFolder, 0),
		teams:         make(map[string]*EnterpriseTeam),
		folders:       make(map[string]*Folder),
	}
}
func (vd *vaultData) VaultStorage() VaultStorage {
	return vd.storage
}
func (vd *vaultData) ClientKey() []byte {
	return vd.clientKey
}
func (vd *vaultData) RootFolder() *Folder {
	return vd.rootFolder
}
func (vd *vaultData) GetRecord(uid string) *PasswordRecord {
	if vd.records != nil {
		return vd.records[uid]
	}
	return nil
}
func (vd *vaultData) GetAllRecords(fn func (*PasswordRecord) bool) {
	if vd.records != nil {
		for _, v := range vd.records {
			if !fn(v) {
				break
			}
		}
	}
}
func (vd *vaultData) RecordCount() int {
	return len(vd.records)
}
func (vd *vaultData) GetSharedFolder(uid string) *SharedFolder {
	if vd.sharedFolders != nil {
		return vd.sharedFolders[uid]
	}
	return nil
}
func (vd *vaultData) GetAllSharedFolders(fn func (*SharedFolder) bool) {
	if vd.sharedFolders != nil {
		for _, v := range vd.sharedFolders {
			if !fn(v) {
				break
			}
		}
	}
}
func (vd *vaultData) SharedFolderCount() int {
	return len(vd.sharedFolders)
}

func (vd *vaultData) GetTeam(uid string) *EnterpriseTeam {
	if vd.teams != nil {
		return vd.teams[uid]
	}
	return nil
}
func (vd *vaultData) GetAllTeams(fn func (*EnterpriseTeam) bool) {
	if vd.teams != nil {
		for _, v := range vd.teams {
			if !fn(v) {
				break
			}
		}
	}
}
func (vd *vaultData) TeamCount() int {
	return len(vd.teams)
}
func (vd *vaultData) GetFolder(uid string) *Folder {
	if vd.folders != nil {
		return vd.folders[uid]
	}
	return nil
}
func (vd *vaultData) GetAllFolders(fn func (*Folder) bool) {
	if vd.folders != nil {
		for _, v := range vd.folders {
			if !fn(v) {
				break
			}
		}
	}
}

func (vd *vaultData) rebuildData(changes *rebuildTask) {
	fullRebuild := changes == nil || changes.isFullSync

	var err error

	vd.teams = make(map[string]*EnterpriseTeam)

	var teamUid string
	var uids = make(map[string]struct{}, 0)
	vd.storage.Teams().Enumerate(func (st StorageTeam) bool {
		var teamKey []byte
		teamUid = st.TeamUid()
		vd.storage.TeamKeys().GetLinksForSubject(teamUid, func (key StorageTeamKey) bool {
			if key.EncryptorUid() == vd.storage.PersonalScopeUid() {
				switch key.KeyType() {
				case UserClientKey:
					if teamKey, err = DecryptAesV1(Base64UrlDecode(key.TeamKey()), vd.clientKey); err == nil {
						return false
					}
				}
			}
			return true
		})
		if teamKey != nil {
			if team, err := NewTeamFromStorage(st, teamKey); err == nil {
				vd.teams[teamUid] = team
			}
		} else {
			uids[teamUid] = empty
		}
		return true
	})
	if len(uids) > 0 {
		for teamUid = range uids {
			vd.VaultStorage().Teams().Delete(teamUid)
		}
	}

	var sharedFolderUid string
	if fullRebuild {
		vd.sharedFolders = make(map[string]*SharedFolder)
	} else {
		if changes != nil && changes.sharedFolders != nil {
			for sharedFolderUid = range changes.sharedFolders {
				delete(vd.sharedFolders, sharedFolderUid)
			}
		}
	}

	enumerateSharedFolders := func (fn func (StorageSharedFolder) bool )  {
		if fullRebuild {
			vd.VaultStorage().SharedFolders().Enumerate(fn)
		} else {
			for sharedFolderUid = range changes.sharedFolders {
				ssf := vd.VaultStorage().SharedFolders().Get(sharedFolderUid)
				if ssf != nil {
					if !fn(ssf) {
						break
					}
				}
			}
		}
	}
	uids = make(map[string]struct{}, 0)
	enumerateSharedFolders(func (ssf StorageSharedFolder) bool {
		var sharedFolderKey []byte = nil
		sharedFolderUid = ssf.SharedFolderUid()
		vd.VaultStorage().SharedFolderKeys().GetLinksForSubject(sharedFolderUid, func (sfk StorageSharedFolderKey) bool {
			switch sfk.KeyType() {
			case UserClientKey:
				if sfk.EncryptorUid() == vd.VaultStorage().PersonalScopeUid() {
					sharedFolderKey, _ = DecryptAesV1(Base64UrlDecode(sfk.SharedFolderKey()), vd.ClientKey())
				}
			case TeamKey:
				if team := vd.GetTeam(sfk.EncryptorUid()); team != nil {
					sharedFolderKey, _ = DecryptAesV1(Base64UrlDecode(sfk.SharedFolderKey()), team.teamKey)
				}
			}
			return sharedFolderKey == nil
		})
		if sharedFolderKey != nil {
			var recordPermissions = make([]StorageRecordKey, 0, 20)
			vd.VaultStorage().RecordKeys().GetLinksForObject(sharedFolderUid, func (link StorageRecordKey) bool {
				recordPermissions = append(recordPermissions, link); return true
			})
			var userPermissions = make([]StorageSharedFolderPermission, 0, 20)
			vd.VaultStorage().SharedFolderPermissions().GetLinksForSubject(sharedFolderUid, func (link StorageSharedFolderPermission) bool {
				userPermissions = append(userPermissions, link); return true
			})
			sharedFolder := NewSharedFolderFromStorage(ssf, userPermissions, recordPermissions, sharedFolderKey)
			vd.sharedFolders[sharedFolderUid] = sharedFolder
		} else {
			uids[sharedFolderUid] = empty
		}
		return true
	})
	if len(uids) > 0 {
		for sharedFolderUid = range uids {
			vd.VaultStorage().SharedFolders().Delete(sharedFolderUid)
		}
	}

	var recordUid string
	if fullRebuild {
		vd.records = make(map[string]*PasswordRecord)
	} else {
		for recordUid = range changes.records {
			delete(vd.records, recordUid)
		}
	}

	enumerateRecords := func (fn func (StorageRecord) bool)  {
		if fullRebuild {
			vd.VaultStorage().Records().Enumerate(fn)
		} else {
			for recordUid = range changes.records {
				sr := vd.VaultStorage().Records().Get(recordUid)
				if sr != nil {
					if !fn(sr) {
						break
					}
				}
			}
		}
	}

	uids = make(map[string]struct{}, 0)
	enumerateRecords(func (sr StorageRecord) bool {
		recordUid = sr.RecordUid()
		var recordKey []byte = nil
		vd.VaultStorage().RecordKeys().GetLinksForSubject(recordUid, func (srk StorageRecordKey) bool {
			switch StorageKeyType(srk.KeyType()) {
			case NoRecordKey, UserClientKey, UserPublicKey:
				if srk.EncryptorUid() == vd.VaultStorage().PersonalScopeUid() {
					recordKey, _ = DecryptAesV1(Base64UrlDecode(srk.RecordKey()), vd.ClientKey())
				}
			case SharedFolderKey:
				sharedFolder := vd.GetSharedFolder(srk.EncryptorUid())
				if sharedFolder != nil {
					recordKey, _ = DecryptAesV1(Base64UrlDecode(srk.RecordKey()), sharedFolder.sharedFolderKey)
				}
			}
			return recordKey == nil
		})
		if recordKey != nil {
			if record, err := NewPasswordRecordFromStorage(sr, recordKey); err == nil {
				vd.records[recordUid] = record
			}
		} else {
			uids[recordUid] = empty
		}
		return true
	})
	if len(uids) > 0 {
		for recordUid = range uids {
			vd.VaultStorage().Records().Delete(recordUid)
		}
	}

	vd.buildFolders()
}

func (vd *vaultData) buildFolders() {
	var err error
	vd.folders = make(map[string]*Folder, 20)
	vd.rootFolder.records = make(set, 20)
	vd.rootFolder.subfolders = make(set, 10)
	vd.VaultStorage().Folders().Enumerate(func (sf StorageFolder) bool {
		folderUid := sf.FolderUid()
		folder := & Folder{
			FolderUid:       folderUid,
			FolderType:      sf.FolderType(),
			ParentUid:       sf.ParentUid(),
			SharedFolderUid: sf.SharedFolderUid(),
			subfolders:      make(set, 20),
			records:         make(set, 20),
		}
		var data []byte = nil
		var key []byte
		switch sf.FolderType() {
		case "user_folder":
			if key, err = DecryptAesV1(Base64UrlDecode(sf.FolderKey()), vd.clientKey); err == nil {
				data, _ = DecryptAesV1(Base64UrlDecode(sf.Data()), key)
			}
		case "shared_folder":
			sharedFolder := vd.GetSharedFolder(sf.SharedFolderUid())
			if sharedFolder != nil {
				folder.Name = sharedFolder.Name
			}
		case "shared_folder_folder":
			sharedFolder := vd.GetSharedFolder(sf.SharedFolderUid())
			if sharedFolder != nil {
				if key, err = DecryptAesV1(Base64UrlDecode(sf.FolderKey()), sharedFolder.sharedFolderKey); err == nil {
					data, _ = DecryptAesV1(Base64UrlDecode(sf.Data()), key)
				}
			}
		}
		if folder.Name == "" {
			if data != nil {
				dict := make(map[string]interface{})
				if err = json.Unmarshal(data, &dict); err == nil {
					v := dict["name"]
					if v != nil {
						folder.Name = v.(string)
					}
				}
			}
		}
		if folder.Name == "" {
			folder.Name = folderUid
		}
		vd.folders[folderUid] = folder
		return true
	})
	for k, v := range vd.folders {
		var parent *Folder
		if parent = vd.folders[v.ParentUid]; parent == nil {
			parent = vd.rootFolder
		}
		parent.subfolders[k] = empty
	}

	vd.storage.FolderRecords().GetAllLinks(func (sfr StorageFolderRecord) bool {
		var folder *Folder
		if folder = vd.folders[sfr.FolderUid()]; folder == nil {
			folder = vd.rootFolder
		}
		folder.records[sfr.RecordUid()] = empty
		return true
	})
}