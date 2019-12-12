package sdk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"gotest.tools/assert"
	"testing"
	"time"
)

func TestVault_SyncDown(t *testing.T) {
	vault, _ := newTestVault()
	_ = <-vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == 3)
	assert.Assert(t, vault.SharedFolderCount() == 1)
	assert.Assert(t, vault.TeamCount() == 1)
}

func TestVault_SyncDownRemoveOwnedRecord(t *testing.T) {
	vault, mock := newTestVault()
	_ = <-vault.SyncDown()
	recordsBefore := vault.RecordCount()
	toRemove := make([]string, 0)
	vault.VaultStorage().Records().Enumerate(func(sr StorageRecord) bool {
		if sr.Owner() {
			toRemove = append(toRemove, sr.RecordUid())
		}
		return true
	})
	revision := vault.VaultStorage().Revision() + 10
	mock.mockSyncDownResponse = &SyncDownResponse{
		KeeperApiResponse: KeeperApiResponse{
			Result: "success",
		},
		FullSync:       false,
		Revision:       revision,
		RemovedRecords: toRemove,
	}
	_ = <-vault.SyncDown()

	assert.Assert(t, vault.RecordCount() == recordsBefore-len(toRemove))
	assert.Assert(t, vault.SharedFolderCount() == 1)
	assert.Assert(t, vault.TeamCount() == 1)
	assert.Assert(t, vault.VaultStorage().Revision() == revision)
}

func TestVault_SyncDownRemoveTeam(t *testing.T) {
	vault, mock := newTestVault()
	_ = <-vault.SyncDown()

	recordsBefore := vault.RecordCount()
	sharedFoldersBefore := vault.SharedFolderCount()

	toRemove := make([]string, 0)
	vault.GetAllTeams(func (t *EnterpriseTeam) bool {
		toRemove = append(toRemove, t.TeamUid)
		return true
	})

	revision := vault.VaultStorage().Revision() + 10
	mock.mockSyncDownResponse = &SyncDownResponse{
		KeeperApiResponse: KeeperApiResponse{
			Result: "success",
		},
		FullSync:     false,
		Revision:     revision,
		RemovedTeams: toRemove,
	}
	_ = <-vault.SyncDown()

	assert.Assert(t, vault.RecordCount() == recordsBefore)
	assert.Assert(t, vault.SharedFolderCount() == sharedFoldersBefore)
	assert.Assert(t, vault.TeamCount() == 0)
}

func TestVault_SyncDownRemoveSharedFolderThenTeam(t *testing.T) {
	vault, mock := newTestVault()
	_ = <-vault.SyncDown()

	recordsBefore := vault.RecordCount()
	sharedFoldersBefore := vault.SharedFolderCount()
	teamsBefore := vault.TeamCount()

	toRemove := make([]string, 0)
	vault.GetAllSharedFolders(func (sf *SharedFolder) bool {
		toRemove = append(toRemove, sf.SharedFolderUid)
		return true
	})

	revision := vault.VaultStorage().Revision() + 10
	mock.mockSyncDownResponse = &SyncDownResponse{
		KeeperApiResponse: KeeperApiResponse{
			Result: "success",
		},
		FullSync:     false,
		Revision:     revision,
		RemovedSharedFolders: toRemove,
	}
	_ = <-vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == recordsBefore)
	assert.Assert(t, vault.SharedFolderCount() == sharedFoldersBefore)
	assert.Assert(t, vault.TeamCount() == teamsBefore)


	recordsBefore = vault.RecordCount()
	sharedFoldersBefore = vault.SharedFolderCount()
	teamsBefore = vault.TeamCount()

	toRemove = make([]string, 0)
	vault.GetAllTeams(func (t *EnterpriseTeam) bool {
		toRemove = append(toRemove, t.TeamUid)
		return true
	})

	revision = vault.VaultStorage().Revision() + 10
	mock.mockSyncDownResponse = &SyncDownResponse{
		KeeperApiResponse: KeeperApiResponse{
			Result: "success",
		},
		FullSync:     false,
		Revision:     revision,
		RemovedTeams: toRemove,
	}
	_ = <-vault.SyncDown()

	assert.Assert(t, vault.RecordCount() == 2)
	assert.Assert(t, vault.SharedFolderCount() == 0)
	assert.Assert(t, vault.TeamCount() == 0)
}

func TestVault_SyncDownRemoveSharedFolderAndTeam(t *testing.T) {
	vault, mock := newTestVault()
	_ = <-vault.SyncDown()

	sfToRemove := make([]string, 0)
	vault.GetAllSharedFolders(func(sf *SharedFolder) bool {
		sfToRemove = append(sfToRemove, sf.SharedFolderUid)
		return true
	})

	teamToRemove := make([]string, 0)
	vault.GetAllTeams(func (t *EnterpriseTeam) bool {
		teamToRemove = append(teamToRemove, t.TeamUid)
		return true
	})

	revision := vault.VaultStorage().Revision() + 10
	mock.mockSyncDownResponse = &SyncDownResponse{
		KeeperApiResponse: KeeperApiResponse{
			Result: "success",
		},
		FullSync:             false,
		Revision:             revision,
		RemovedSharedFolders: sfToRemove,
		RemovedTeams:         teamToRemove,
	}
	_ = <-vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == 2)
	assert.Assert(t, vault.SharedFolderCount() == 0)
	assert.Assert(t, vault.TeamCount() == 0)
}

//////////////
func newTestVault() (v Vault, a *authMock) {
	a = newAuthMock()
	a.context.Username = defaultVaultContext.username
	a.context.DataKey = defaultVaultContext.dataKey
	a.context.ClientKey = defaultVaultContext.clientKey
	a.context.SessionToken = defaultVaultContext.sessionToken
	a.context.PrivateKey = defaultVaultContext.privateKey
	v = &vault{
		VaultData: NewVaultData(a.AuthContext().ClientKey, NewInMemoryVaultStorage()),
		Auth:      a,
	}
	return
}
type authMock struct {
	context *AuthContext
	mockMethodCalled

	fullSyncDownResponse *SyncDownResponse
	mockSyncDownResponse *SyncDownResponse
}
func newAuthMock() *authMock {
	result := &authMock{
		context:          new(AuthContext),
		fullSyncDownResponse: new(SyncDownResponse),
	}
	records := make([]*SyncDownRecord, 0)
	metaDatas := make([]*SyncDownRecordMetaData, 0)
	sharedFolders := make([]*SyncDownSharedFolder, 0)
	teams := make([]*SyncDownTeam, 0)
	userFolders := make([]*SyncDownUserFolder, 0)
	userFolderRecords := make([]*SyncDownFolderRecordNode, 0)
	userFolderSharedFolders := make([]*SyncDownUserFolderSharedFolder, 0)

	r1 := &PasswordRecord{
		RecordUid: GenerateUid(),
		Title:     "Record 1",
		Login:     "user1@keepersecurity.com",
		Password:  "password1",
		Link:      "https://keepersecurity.com/1",
		Notes:     "note1",
		owner:     true,
		recordKey: GenerateAesKey(),
	}
	r1.SetCustomField("field1", "value1")
	r1.Attachments = make([]*AttachmentFile, 0)
	atta := &AttachmentFile{
		Id:   "ABCDEFGH",
		Name: "Attachment 1",
		Size: 1000,
		Key:  GenerateAesKey(),
	}
	r1.Attachments = append(r1.Attachments, atta)
	r, md := registerRecord(r1, 1)
	r.Revision_ = 1
	records = append(records, r)
	if md != nil {
		metaDatas = append(metaDatas, md)
	}
	r2 := &PasswordRecord{
		RecordUid: GenerateUid(),
		Title:     "Record 2",
		Login:     "user2@keepersecurity.com",
		Password:  "password2",
		Link:      "https://keepersecurity.com/2",
		Notes:     "note2",
		owner:     false,
		recordKey: GenerateAesKey(),
	}
	r, md = registerRecord(r2, 2)
	r.Revision_ = 2
	records = append(records, r)
	if md != nil {
		metaDatas = append(metaDatas, md)
	}

	r3 := &PasswordRecord{
		RecordUid: GenerateUid(),
		Title:     "Record 3",
		Login:     "user3@keepersecurity.com",
		Password:  "password3",
		Link:      "https://keepersecurity.com/3",
		owner:     false,
		recordKey: GenerateAesKey(),
	}
	r, _ = registerRecord(r3, 3)
	r.Revision_ = 3
	records = append(records, r)

	sf1 := &SharedFolder{
		SharedFolderUid:      GenerateUid(),
		Name:                 "Shared Folder 1",
		DefaultManageRecords: false,
		DefaultManageUsers:   false,
		DefaultCanEdit:       false,
		DefaultCanShare:      false,
		sharedFolderKey:      GenerateAesKey(),
	}
	sf := registerSharedFolder(sf1, 1, []*PasswordRecord{r3})
	sf.Revision_ = 4
	sharedFolders = append(sharedFolders, sf)

	t1 := &EnterpriseTeam{
		TeamUid:       GenerateUid(),
		Name:          "Team 1",
		RestrictEdit:  true,
		RestrictShare: true,
		RestrictView:  false,
		teamKey:       GenerateAesKey(),
		privateKey:    defaultVaultContext.privateKey,
	}
	team := registerTeam(t1, 1, []*SharedFolder{sf1})
	sft := &SyncDownSharedFolderTeam{
		TeamUid:         team.TeamUid_,
		Name_:           team.Name_,
		ManageRecords_:  true,
		ManageUsers_:    false,
		sharedFolderUid: sf.SharedFolderUid_,
	}
	sf.Teams = append(sf.Teams, sft)
	teams = append(teams, team)

	uf1 := &Folder{
		FolderUid:  GenerateUid(),
		FolderType: "user_folder",
		Name:       "User Folder 1",
	}
	uf := registerUserFolder(uf1)
	userFolders = append(userFolders, uf)
	userFolderSharedFolders = append(userFolderSharedFolders, &SyncDownUserFolderSharedFolder{
		SharedFolderUid_: sf1.SharedFolderUid,
	})

	userFolderRecords = append(userFolderRecords, &SyncDownFolderRecordNode{
		RecordUid_: r1.RecordUid,
	})
	userFolderRecords = append(userFolderRecords, &SyncDownFolderRecordNode{
		RecordUid_:         r1.RecordUid,
		SyncDownFolderNode: SyncDownFolderNode{FolderUid_: sf1.SharedFolderUid},
	})
	userFolderRecords = append(userFolderRecords, &SyncDownFolderRecordNode{
		RecordUid_:         r2.RecordUid,
		SyncDownFolderNode: SyncDownFolderNode{FolderUid_: uf1.FolderUid,},
	})
	userFolderRecords = append(userFolderRecords, &SyncDownFolderRecordNode{
		RecordUid_:         r3.RecordUid,
		SyncDownFolderNode: SyncDownFolderNode{FolderUid_: sf1.SharedFolderUid,},
	})

	result.fullSyncDownResponse.Revision = 100
	result.fullSyncDownResponse.FullSync = true
	result.fullSyncDownResponse.Records = records
	result.fullSyncDownResponse.RecordMetaData = metaDatas
	result.fullSyncDownResponse.SharedFolders = sharedFolders
	result.fullSyncDownResponse.Teams = teams
	result.fullSyncDownResponse.UserFolders = userFolders
	result.fullSyncDownResponse.UserFolderSharedFolders = userFolderSharedFolders
	result.fullSyncDownResponse.UserFolderRecords = userFolderRecords

	return result
}

func (am *authMock) AuthContext() *AuthContext {
	return am.context
}
func (am *authMock) Ui() AuthUI {
	return nil
}
func (am *authMock) SettingsStorage() ISettingsStorage {
	return nil
}
func (am *authMock) Endpoint() KeeperEndpoint {
	return nil
}
func (am *authMock) IsAuthenticated() bool {
	return true
}
func (am *authMock) Login(string, string) error {
	return errors.New("not implemented")
}
func (am *authMock) Logout() {}
func (am *authMock) ExecuteAuthCommand(rq interface{}, rs interface{}, _ bool) (err error) {
	if toCmd, ok := rq.(ToKeeperApiCommand); ok {
		apiRq := toCmd.GetKeeperApiCommand()
		if apiRq.Command == "" {
			if cmdName, ok := rq.(ICommand); ok {
				apiRq.Command = cmdName.Command()
			}
		}
		am.incMethodCalled(toCmd.GetKeeperApiCommand().Command)
	}
	switch command := rq.(type) {
	case *SyncDownCommand:
		if response, ok := rs.(*SyncDownResponse); ok {
		if command.Revision == 0 {
				*response = *am.fullSyncDownResponse
			} else if am.mockSyncDownResponse != nil {
				*response = *am.mockSyncDownResponse
			} else {
				response.Result = "fail"
				response.ResultCode = "mock_error"
			}
		}
	default:
		err = errors.New("not implemented")
	}
	return
}

func registerRecord(record *PasswordRecord, keyType int32) (sdr *SyncDownRecord, sdrmd *SyncDownRecordMetaData) {
	if data, extra, udata, err := record.Serialize(nil); err == nil {
		sdr = &SyncDownRecord{
			RecordUid_:          record.RecordUid,
			Version_:            2,
			ClientModifiedTime_: time.Now().Unix(),
			Shared_:             (keyType != 0) && (keyType != 1),
			owner:               (keyType == 0) || (keyType == 1),
		}
		if data != nil {
			if data, err = EncryptAesV1(data, record.recordKey); err != nil {
				return
			}
			sdr.Data_ = Base64UrlEncode(data)
		}
		if extra != nil {
			if extra, err = EncryptAesV1(extra, record.recordKey); err == nil {
				sdr.Extra_ = Base64UrlEncode(extra)
			}
		}
		if udata != nil {
			sdr.Udata_ = make(map[string]interface{})
			_ = json.Unmarshal(udata, &sdr.Udata_)
		}

		if keyType == 1 || keyType == 2 {
			var key []byte
			if keyType == 1 {
				key, _ = EncryptAesV1(record.recordKey, defaultVaultContext.dataKey)
			} else {
				key, _ = EncryptRsa(record.recordKey, defaultVaultContext.publicKey)
			}
			sdrmd = &SyncDownRecordMetaData{
				RecordUid_:     record.RecordUid,
				RecordKey_:     Base64UrlEncode(key),
				RecordKeyType_: keyType,
				Owner:          record.owner,
				CanShare_:      keyType == 1,
				CanEdit_:       keyType == 1,
			}
		}
	}
	return
}

func registerSharedFolder(sharedFolder *SharedFolder, keyType int32, records []*PasswordRecord) (sdsf *SyncDownSharedFolder) {
	name, _ := EncryptAesV1([]byte(sharedFolder.Name), sharedFolder.sharedFolderKey)
	sdsf = &SyncDownSharedFolder{
		SharedFolderUid_:      sharedFolder.SharedFolderUid,
		Name_:                 Base64UrlEncode(name),
		DefaultManageRecords_: false,
		DefaultManageUsers_:   false,
		DefaultCanEdit_:       false,
		DefaultCanShare_:      false,
		FullSync:              true,
		Records:               make([]*SyncDownSharedFolderRecord, 0),
		Users:                 make([]*SyncDownSharedFolderUser, 0),
		Teams:                 make([]*SyncDownSharedFolderTeam, 0),
	}
	var encKey []byte = nil
	if keyType == 1 {
		encKey, _ = EncryptAesV1(sharedFolder.sharedFolderKey, defaultVaultContext.dataKey)
	} else if keyType == 2 {
		encKey, _ = EncryptRsa(sharedFolder.sharedFolderKey, defaultVaultContext.publicKey)
	}
	if encKey != nil {
		var t = new(bool)
		if keyType == 1 {
			*t = true
		} else {
			*t = false
		}
		var s = Base64UrlEncode(encKey)
		sdsf.SharedFolderKey = &s
		sdsf.KeyType = &keyType
		sdsf.ManageRecords = t
		sdsf.ManageUsers = t
	}
	sdsf.Users = append(sdsf.Users, & SyncDownSharedFolderUser{
		Username:        defaultVaultContext.username,
		ManageRecords_: true,
		ManageUsers_:   false,
	})
	if records != nil {
		for _, r := range records {
			if key, err := EncryptAesV1(r.recordKey, sharedFolder.sharedFolderKey); err == nil {
				sdsfr := & SyncDownSharedFolderRecord{
					RecordUid: r.RecordUid,
					RecordKey: Base64UrlEncode(key),
					CanShare:  false,
					CanEdit:   true,
				}
				sdsf.Records = append(sdsf.Records, sdsfr)
			}
		}
	}
	return
}

func registerTeam(team *EnterpriseTeam, keyType int32, sharedFolders []*SharedFolder) (sdt *SyncDownTeam) {
	var key []byte
	if keyType == 1 {
		key, _ = EncryptAesV1(team.teamKey, defaultVaultContext.dataKey)
	} else if keyType == 2 {
		key, _ = EncryptRsa(team.teamKey, defaultVaultContext.publicKey)
	}
	var pk []byte
	var err error
	if k, ok := team.privateKey.(*rsa.PrivateKey); ok {
		pk = x509.MarshalPKCS1PrivateKey(k)
		if pk, err = EncryptAesV1(pk, team.teamKey); err == nil {
			sdt = &SyncDownTeam{
				TeamUid_:         team.TeamUid,
				Name_:            team.Name,
				TeamKey_:         Base64UrlEncode(key),
				TeamKeyType_:     keyType,
				TeamPrivateKey_:  Base64UrlEncode(pk),
				RestrictEdit_:    false,
				RestrictShare_:   true,
				RestrictView_:    false,
				SharedFolderKeys: make([]*SyncDownSharedFolderKey, 0),
			}
			if sharedFolders != nil {
				for _, sf := range sharedFolders {
					key, _ = EncryptAesV1(sf.sharedFolderKey, team.teamKey)
					sdsfk := &SyncDownSharedFolderKey{
						SharedFolderUid_: sf.SharedFolderUid,
						SharedFolderKey_: Base64UrlEncode(key),
						KeyType_:         1,
					}
					sdt.SharedFolderKeys = append(sdt.SharedFolderKeys, sdsfk)
				}
			}
		}
	}
	return
}

func registerUserFolder(userFolder *Folder) (sduf *SyncDownUserFolder) {
	var key = GenerateAesKey()
	var data = make(map[string]interface{})
	data["name"] = userFolder.Name
	jData, _ := json.Marshal(&data)
	jData, _ = EncryptAesV1(jData, defaultVaultContext.dataKey)
	sduf = &SyncDownUserFolder{
		SyncDownFolderNode: SyncDownFolderNode{
			FolderUid_: userFolder.FolderUid,
		},
		FolderType_:    "user_folder",
		ParentUid_:     userFolder.ParentUid,
		UserFolderKey_: Base64UrlEncode(key),
		KeyType_:       1,
		Data_:          Base64UrlEncode(jData),
	}

	return
}