package mock

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"keepersecurity.com/sdk"
	"time"
)

func NewMockVault(vaultStorage sdk.IVaultStorage) (v sdk.Vault, auth *AuthMock) {
	auth = newAuthMock()
	auth.context.Username = defaultVaultContext.username
	auth.context.DataKey = defaultVaultContext.dataKey
	auth.context.ClientKey = defaultVaultContext.clientKey
	auth.context.SessionToken = defaultVaultContext.sessionToken
	auth.context.PrivateKey = defaultVaultContext.privateKey

	v = sdk.NewVault(auth, vaultStorage)
	return
}

type AuthMock struct {
	context *sdk.AuthContext
	mockMethodCalled

	fullSyncDownResponse *sdk.SyncDownResponse
	MockSyncDownResponse *sdk.SyncDownResponse
}
func newAuthMock() *AuthMock {
	result := &AuthMock{
		context:              new(sdk.AuthContext),
		fullSyncDownResponse: new(sdk.SyncDownResponse),
	}
	records := make([]*sdk.SyncDownRecord, 0)
	metaDatas := make([]*sdk.SyncDownRecordMetaData, 0)
	sharedFolders := make([]*sdk.SyncDownSharedFolder, 0)
	teams := make([]*sdk.SyncDownTeam, 0)
	userFolders := make([]*sdk.SyncDownUserFolder, 0)
	userFolderRecords := make([]*sdk.SyncDownFolderRecordNode, 0)
	userFolderSharedFolders := make([]*sdk.SyncDownUserFolderSharedFolder, 0)

	r1 := &sdk.PasswordRecord{
		RecordUid: sdk.GenerateUid(),
		Title:     "Record 1",
		Login:     "user1@keepersecurity.com",
		Password:  "password1",
		Link:      "https://keepersecurity.com/1",
		Notes:     "note1",
	}
	r1Key := sdk.GenerateAesKey()
	r1.SetCustomField("field1", "value1")
	r1.Attachments = make([]*sdk.AttachmentFile, 0)
	atta := &sdk.AttachmentFile{
		Id:   "ABCDEFGH",
		Name: "Attachment 1",
		Size: 1000,
		Key:  sdk.GenerateAesKey(),
	}
	r1.Attachments = append(r1.Attachments, atta)
	r, md := registerRecord(r1, r1Key, 1)
	r.Revision_ = 1
	records = append(records, r)
	if md != nil {
		metaDatas = append(metaDatas, md)
	}
	r2 := &sdk.PasswordRecord{
		RecordUid: sdk.GenerateUid(),
		Title:     "Record 2",
		Login:     "user2@keepersecurity.com",
		Password:  "password2",
		Link:      "https://keepersecurity.com/2",
		Notes:     "note2",
	}
	r2Key := sdk.GenerateAesKey()
	r, md = registerRecord(r2, r2Key, 2)
	r.Revision_ = 2
	records = append(records, r)
	if md != nil {
		metaDatas = append(metaDatas, md)
	}

	r3 := &sdk.PasswordRecord{
		RecordUid: sdk.GenerateUid(),
		Title:     "Record 3",
		Login:     "user3@keepersecurity.com",
		Password:  "password3",
		Link:      "https://keepersecurity.com/3",
	}
	r3Key := sdk.GenerateAesKey()
	r, _ = registerRecord(r3, r3Key, 3)
	r.Revision_ = 3
	records = append(records, r)

	sf1 := &sdk.SharedFolder{
		SharedFolderUid:      sdk.GenerateUid(),
		Name:                 "Shared Folder 1",
		DefaultManageRecords: false,
		DefaultManageUsers:   false,
		DefaultCanEdit:       false,
		DefaultCanShare:      false,
	}
	sf1Key := sdk.GenerateAesKey()
	sf := registerSharedFolder(sf1, sf1Key, 1, map[string][]byte{r3.RecordUid: r3Key})
	sf.Revision_ = 4
	sharedFolders = append(sharedFolders, sf)

	t1 := &sdk.EnterpriseTeam{
		TeamUid:       sdk.GenerateUid(),
		Name:          "Team 1",
		RestrictEdit:  true,
		RestrictShare: true,
		RestrictView:  false,
	}
	t1Key := sdk.GenerateAesKey()
	t1PrivateKey := defaultVaultContext.privateKey
	team := registerTeam(t1, t1Key, t1PrivateKey, 1, map[string][]byte{sf1.SharedFolderUid: sf1Key})
	sft := &sdk.SyncDownSharedFolderTeam{
		TeamUid:        team.TeamUid_,
		Name_:          team.Name_,
		ManageRecords_: true,
		ManageUsers_:   false,
	}
	sf.Teams = append(sf.Teams, sft)
	teams = append(teams, team)

	uf1 := &sdk.Folder{
		FolderUid:  sdk.GenerateUid(),
		FolderType: "user_folder",
		Name:       "User Folder 1",
	}
	uf := registerUserFolder(uf1)
	userFolders = append(userFolders, uf)
	userFolderSharedFolders = append(userFolderSharedFolders, &sdk.SyncDownUserFolderSharedFolder{
		SharedFolderUid_: sf1.SharedFolderUid,
	})

	userFolderRecords = append(userFolderRecords, &sdk.SyncDownFolderRecordNode{
		RecordUid_: r1.RecordUid,
	})
	userFolderRecords = append(userFolderRecords, &sdk.SyncDownFolderRecordNode{
		RecordUid_:         r1.RecordUid,
		SyncDownFolderNode: sdk.SyncDownFolderNode{FolderUid_: sf1.SharedFolderUid},
	})
	userFolderRecords = append(userFolderRecords, &sdk.SyncDownFolderRecordNode{
		RecordUid_:         r2.RecordUid,
		SyncDownFolderNode: sdk.SyncDownFolderNode{FolderUid_: uf1.FolderUid,},
	})
	userFolderRecords = append(userFolderRecords, &sdk.SyncDownFolderRecordNode{
		RecordUid_:         r3.RecordUid,
		SyncDownFolderNode: sdk.SyncDownFolderNode{FolderUid_: sf1.SharedFolderUid,},
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

func (am *AuthMock) AuthContext() *sdk.AuthContext {
	return am.context
}
func (am *AuthMock) Ui() sdk.AuthUI {
	return nil
}
func (am *AuthMock) SettingsStorage() sdk.ISettingsStorage {
	return nil
}
func (am *AuthMock) Endpoint() sdk.KeeperEndpoint {
	return nil
}
func (am *AuthMock) IsAuthenticated() bool {
	return true
}
func (am *AuthMock) Login(string, string) error {
	return errors.New("not implemented")
}
func (am *AuthMock) Logout() {}
func (am *AuthMock) ExecuteAuthCommand(rq interface{}, rs interface{}, _ bool) (err error) {
	if toCmd, ok := rq.(sdk.ToKeeperApiCommand); ok {
		apiRq := toCmd.GetKeeperApiCommand()
		if apiRq.Command == "" {
			if cmdName, ok := rq.(sdk.ICommand); ok {
				apiRq.Command = cmdName.Command()
			}
		}
		am.incMethodCalled(toCmd.GetKeeperApiCommand().Command)
	}
	switch command := rq.(type) {
	case *sdk.SyncDownCommand:
		if response, ok := rs.(*sdk.SyncDownResponse); ok {
			if command.Revision == 0 {
				*response = *am.fullSyncDownResponse
			} else if am.MockSyncDownResponse != nil {
				*response = *am.MockSyncDownResponse
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

func registerRecord(record *sdk.PasswordRecord, recordKey []byte, keyType int32) (sdr *sdk.SyncDownRecord, sdrmd *sdk.SyncDownRecordMetaData) {
	if data, extra, udata, err := record.Serialize(nil); err == nil {
		sdr = &sdk.SyncDownRecord{
			RecordUid_:          record.RecordUid,
			Version_:            2,
			ClientModifiedTime_: time.Now().Unix(),
			Shared_:             (keyType != 0) && (keyType != 1),
		}
		if data != nil {
			if data, err = sdk.EncryptAesV1(data, recordKey); err != nil {
				return
			}
			sdr.Data_ = sdk.Base64UrlEncode(data)
		}
		if extra != nil {
			if extra, err = sdk.EncryptAesV1(extra, recordKey); err == nil {
				sdr.Extra_ = sdk.Base64UrlEncode(extra)
			}
		}
		if udata != nil {
			sdr.Udata_ = udata
		}

		if keyType == 1 || keyType == 2 {
			var key []byte
			if keyType == 1 {
				key, _ = sdk.EncryptAesV1(recordKey, defaultVaultContext.dataKey)
			} else {
				key, _ = sdk.EncryptRsa(recordKey, defaultVaultContext.publicKey)
			}
			sdrmd = &sdk.SyncDownRecordMetaData{
				RecordUid_:     record.RecordUid,
				RecordKey_:     sdk.Base64UrlEncode(key),
				RecordKeyType_: keyType,
				Owner:          (keyType == 0) || (keyType == 1),
				CanShare_:      keyType == 1,
				CanEdit_:       keyType == 1,
			}
		}
	}
	return
}

func registerSharedFolder(sharedFolder *sdk.SharedFolder, sharedFolderKey []byte, keyType int32, recordKeys map[string][]byte) (sdsf *sdk.SyncDownSharedFolder) {
	name, _ := sdk.EncryptAesV1([]byte(sharedFolder.Name), sharedFolderKey)
	sdsf = &sdk.SyncDownSharedFolder{
		SharedFolderUid_:      sharedFolder.SharedFolderUid,
		Name_:                 sdk.Base64UrlEncode(name),
		DefaultManageRecords_: false,
		DefaultManageUsers_:   false,
		DefaultCanEdit_:       false,
		DefaultCanShare_:      false,
		FullSync:              true,
		Records:               make([]*sdk.SyncDownSharedFolderRecord, 0),
		Users:                 make([]*sdk.SyncDownSharedFolderUser, 0),
		Teams:                 make([]*sdk.SyncDownSharedFolderTeam, 0),
	}
	var encKey []byte = nil
	if keyType == 1 {
		encKey, _ = sdk.EncryptAesV1(sharedFolderKey, defaultVaultContext.dataKey)
	} else if keyType == 2 {
		encKey, _ = sdk.EncryptRsa(sharedFolderKey, defaultVaultContext.publicKey)
	}
	if encKey != nil {
		var t = new(bool)
		if keyType == 1 {
			*t = true
		} else {
			*t = false
		}
		var s = sdk.Base64UrlEncode(encKey)
		sdsf.SharedFolderKey = &s
		sdsf.KeyType = &keyType
		sdsf.ManageRecords = t
		sdsf.ManageUsers = t
	}
	sdsf.Users = append(sdsf.Users, &sdk.SyncDownSharedFolderUser{
		Username:        defaultVaultContext.username,
		ManageRecords_: true,
		ManageUsers_:   false,
	})
	if recordKeys != nil {
		for recordUid, recordKey := range recordKeys {
			if key, err := sdk.EncryptAesV1(recordKey, sharedFolderKey); err == nil {
				sdsfr := &sdk.SyncDownSharedFolderRecord{
					RecordUid: recordUid,
					RecordKey: sdk.Base64UrlEncode(key),
					CanShare:  false,
					CanEdit:   true,
				}
				sdsf.Records = append(sdsf.Records, sdsfr)
			}
		}
	}
	return
}

func registerTeam(team *sdk.EnterpriseTeam, teamKey []byte, privateKey crypto.PrivateKey, keyType int32, sfKeys map[string][]byte) (sdt *sdk.SyncDownTeam) {
	var key []byte
	if keyType == 1 {
		key, _ = sdk.EncryptAesV1(teamKey, defaultVaultContext.dataKey)
	} else if keyType == 2 {
		key, _ = sdk.EncryptRsa(teamKey, defaultVaultContext.publicKey)
	}
	var pk []byte
	var err error
	if k, ok := privateKey.(*rsa.PrivateKey); ok {
		pk = x509.MarshalPKCS1PrivateKey(k)
		if pk, err = sdk.EncryptAesV1(pk, teamKey); err == nil {
			sdt = &sdk.SyncDownTeam{
				TeamUid_:         team.TeamUid,
				Name_:            team.Name,
				TeamKey_:         sdk.Base64UrlEncode(key),
				TeamKeyType_:     keyType,
				TeamPrivateKey_:  sdk.Base64UrlEncode(pk),
				RestrictEdit_:    false,
				RestrictShare_:   true,
				RestrictView_:    false,
				SharedFolderKeys: make([]*sdk.SyncDownSharedFolderKey, 0),
			}
			if sfKeys != nil {
				for sfUid, sfKey := range sfKeys {
					key, _ = sdk.EncryptAesV1(sfKey, teamKey)
					sdsfk := &sdk.SyncDownSharedFolderKey{
						SharedFolderUid_: sfUid,
						SharedFolderKey_: sdk.Base64UrlEncode(key),
						KeyType_:         1,
					}
					sdt.SharedFolderKeys = append(sdt.SharedFolderKeys, sdsfk)
				}
			}
		}
	}
	return
}

func registerUserFolder(userFolder *sdk.Folder) (sduf *sdk.SyncDownUserFolder) {
	var key = sdk.GenerateAesKey()
	var data = make(map[string]interface{})
	data["name"] = userFolder.Name
	jData, _ := json.Marshal(&data)
	jData, _ = sdk.EncryptAesV1(jData, defaultVaultContext.dataKey)
	sduf = &sdk.SyncDownUserFolder{
		SyncDownFolderNode: sdk.SyncDownFolderNode{
			FolderUid_: userFolder.FolderUid,
		},
		FolderType_:    "user_folder",
		ParentUid_:     userFolder.ParentUid,
		UserFolderKey_: sdk.Base64UrlEncode(key),
		KeyType_:       1,
		Data_:          sdk.Base64UrlEncode(jData),
	}

	return
}