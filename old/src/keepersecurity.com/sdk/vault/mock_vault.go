package vault

import (
  "crypto"
  "crypto/rsa"
  "crypto/x509"
  "encoding/json"
  "errors"
  "time"

  "google.golang.org/protobuf/proto"
  "keepersecurity.com/sdk/auth"
)

func NewMockVault(vaultStorage IVaultStorage) (v Vault, a *authMock) {
  a = newAuthMock()
  v = NewVault(a, vaultStorage)
  return
}

type authMock struct {
  uiCallback   auth.IAuthUiCallback
  context auth.IAuthContext
  push auth.IPushEndpoint
  fullSyncDownResponse *SyncDownResponse
  MockSyncDownResponse *SyncDownResponse
}

func newAuthMock() *authMock {
  result := &authMock{
    context:              auth.NewAuthContextMock(),
    push:                 new(auth.PushEndpoint),
    fullSyncDownResponse: new(SyncDownResponse),
  }
  result.prepareVaultData()
  return result
}

func (am *authMock) prepareVaultData() {
  records := make([]*SyncDownRecord, 0)
  metaDatas := make([]*SyncDownRecordMetaData, 0)
  sharedFolders := make([]*SyncDownSharedFolder, 0)
  teams := make([]*SyncDownTeam, 0)
  userFolders := make([]*SyncDownUserFolder, 0)
  userFolderRecords := make([]*SyncDownFolderRecordNode, 0)
  userFolderSharedFolders := make([]*SyncDownUserFolderSharedFolder, 0)

  r1 := &PasswordRecord{
    RecordUid: auth.GenerateUid(),
    Title:     "Record 1",
    Login:     "user1@keepersecurity.com",
    Password:  "password1",
    Link:      "https://keepersecurity.com/1",
    Notes:     "note1",
  }
  r1Key := auth.GenerateAesKey()
  r1.SetCustomField("field1", "value1")
  r1.Attachments = make([]*AttachmentFile, 0)
  atta := &AttachmentFile{
    Id:   "ABCDEFGH",
    Name: "Attachment 1",
    Size: 1000,
    Key:  auth.GenerateAesKey(),
  }
  r1.Attachments = append(r1.Attachments, atta)
  r, md := am.registerRecord(r1, r1Key, 1)
  r.Revision_ = 1
  records = append(records, r)
  if md != nil {
    metaDatas = append(metaDatas, md)
  }
  r2 := &PasswordRecord{
    RecordUid: auth.GenerateUid(),
    Title:     "Record 2",
    Login:     "user2@keepersecurity.com",
    Password:  "password2",
    Link:      "https://keepersecurity.com/2",
    Notes:     "note2",
  }
  r2Key := auth.GenerateAesKey()
  r, md = am.registerRecord(r2, r2Key, 2)
  r.Revision_ = 2
  records = append(records, r)
  if md != nil {
    metaDatas = append(metaDatas, md)
  }

  r3 := &PasswordRecord{
    RecordUid: auth.GenerateUid(),
    Title:     "Record 3",
    Login:     "user3@keepersecurity.com",
    Password:  "password3",
    Link:      "https://keepersecurity.com/3",
  }
  r3Key := auth.GenerateAesKey()
  r, _ = am.registerRecord(r3, r3Key, 3)
  r.Revision_ = 3
  records = append(records, r)

  sf1 := &SharedFolder{
    SharedFolderUid:      auth.GenerateUid(),
    Name:                 "Shared Folder 1",
    DefaultManageRecords: false,
    DefaultManageUsers:   false,
    DefaultCanEdit:       false,
    DefaultCanShare:      false,
  }
  sf1Key := auth.GenerateAesKey()
  sf := am.registerSharedFolder(sf1, sf1Key, 1, map[string][]byte{r3.RecordUid: r3Key})
  sf.Revision_ = 4
  sharedFolders = append(sharedFolders, sf)

  t1 := &EnterpriseTeam{
    TeamUid:       auth.GenerateUid(),
    Name:          "Team 1",
    RestrictEdit:  true,
    RestrictShare: true,
    RestrictView:  false,
  }
  t1Key := auth.GenerateAesKey()
  t1PrivateKey := am.AuthContext().RsaPrivateKey()
  team := am.registerTeam(t1, t1Key, t1PrivateKey, 1, map[string][]byte{sf1.SharedFolderUid: sf1Key})
  sft := &SyncDownSharedFolderTeam{
    TeamUid:        team.TeamUid_,
    Name_:          team.Name_,
    ManageRecords_: true,
    ManageUsers_:   false,
  }
  sf.Teams = append(sf.Teams, sft)
  teams = append(teams, team)

  uf1 := &Folder{
    FolderUid:  auth.GenerateUid(),
    FolderType: "user_folder",
    Name:       "User Folder 1",
  }
  uf := am.registerUserFolder(uf1)
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

  am.fullSyncDownResponse.Revision = 100
  am.fullSyncDownResponse.FullSync = true
  am.fullSyncDownResponse.Records = records
  am.fullSyncDownResponse.RecordMetaData = metaDatas
  am.fullSyncDownResponse.SharedFolders = sharedFolders
  am.fullSyncDownResponse.Teams = teams
  am.fullSyncDownResponse.UserFolders = userFolders
  am.fullSyncDownResponse.UserFolderSharedFolders = userFolderSharedFolders
  am.fullSyncDownResponse.UserFolderRecords = userFolderRecords
}
func (am *authMock) registerRecord(record *PasswordRecord, recordKey []byte, keyType int32) (sdr *SyncDownRecord, sdrmd *SyncDownRecordMetaData) {
  if data, extra, udata, err := record.Serialize(nil); err == nil {
    sdr = &SyncDownRecord{
      RecordUid_:          record.RecordUid,
      Version_:            2,
      ClientModifiedTime_: time.Now().Unix(),
      Shared_:             (keyType != 0) && (keyType != 1),
    }
    if data != nil {
      if data, err = auth.EncryptAesV1(data, recordKey); err != nil {
        return
      }
      sdr.Data_ = auth.Base64UrlEncode(data)
    }
    if extra != nil {
      if extra, err = auth.EncryptAesV1(extra, recordKey); err == nil {
        sdr.Extra_ = auth.Base64UrlEncode(extra)
      }
    }
    if udata != nil {
      sdr.Udata_ = udata
    }

    if keyType == 1 || keyType == 2 {
      var key []byte
      if keyType == 1 {
        key, _ = auth.EncryptAesV1(recordKey, am.AuthContext().DataKey())
      } else {
        publicKey, _ := auth.GetRsaPublicKey(am.AuthContext().RsaPrivateKey())
        key, _ = auth.EncryptRsa(recordKey, publicKey)
      }
      sdrmd = &SyncDownRecordMetaData{
        RecordUid_:     record.RecordUid,
        RecordKey_:     auth.Base64UrlEncode(key),
        RecordKeyType_: keyType,
        Owner:          (keyType == 0) || (keyType == 1),
        CanShare_:      keyType == 1,
        CanEdit_:       keyType == 1,
      }
    }
  }
  return
}

func (am *authMock) registerSharedFolder(sharedFolder *SharedFolder, sharedFolderKey []byte, keyType int32, recordKeys map[string][]byte) (sdsf *SyncDownSharedFolder) {
  name, _ := auth.EncryptAesV1([]byte(sharedFolder.Name), sharedFolderKey)
  sdsf = &SyncDownSharedFolder{
    SharedFolderUid_:      sharedFolder.SharedFolderUid,
    Name_:                 auth.Base64UrlEncode(name),
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
    encKey, _ = auth.EncryptAesV1(sharedFolderKey, am.AuthContext().DataKey())
  } else if keyType == 2 {
    publicKey, _ := auth.GetRsaPublicKey(am.AuthContext().RsaPrivateKey())
    encKey, _ = auth.EncryptRsa(sharedFolderKey, publicKey)
  }
  if encKey != nil {
    var t = new(bool)
    if keyType == 1 {
      *t = true
    } else {
      *t = false
    }
    var s = auth.Base64UrlEncode(encKey)
    sdsf.SharedFolderKey = &s
    sdsf.KeyType = &keyType
    sdsf.ManageRecords = t
    sdsf.ManageUsers = t
  }
  sdsf.Users = append(sdsf.Users, &SyncDownSharedFolderUser{
    Username:       am.AuthContext().Username(),
    ManageRecords_: true,
    ManageUsers_:   false,
  })
  if recordKeys != nil {
    for recordUid, recordKey := range recordKeys {
      if key, err := auth.EncryptAesV1(recordKey, sharedFolderKey); err == nil {
        sdsfr := &SyncDownSharedFolderRecord{
          RecordUid_: recordUid,
          RecordKey_: auth.Base64UrlEncode(key),
          CanShare_:  false,
          CanEdit_:   true,
        }
        sdsf.Records = append(sdsf.Records, sdsfr)
      }
    }
  }
  return
}

func (am *authMock) registerTeam(team *EnterpriseTeam, teamKey []byte, privateKey crypto.PrivateKey, keyType int32, sfKeys map[string][]byte) (sdt *SyncDownTeam) {
  var key []byte
  if keyType == 1 {
    key, _ = auth.EncryptAesV1(teamKey, am.AuthContext().DataKey())
  } else if keyType == 2 {
    publicKey, _ := auth.GetRsaPublicKey(am.AuthContext().RsaPrivateKey())
    key, _ = auth.EncryptRsa(teamKey, publicKey)
  }
  var pk []byte
  var err error
  if k, ok := privateKey.(*rsa.PrivateKey); ok {
    pk = x509.MarshalPKCS1PrivateKey(k)
    if pk, err = auth.EncryptAesV1(pk, teamKey); err == nil {
      sdt = &SyncDownTeam{
        TeamUid_:         team.TeamUid,
        Name_:            team.Name,
        TeamKey_:         auth.Base64UrlEncode(key),
        TeamKeyType_:     keyType,
        TeamPrivateKey_:  auth.Base64UrlEncode(pk),
        RestrictEdit_:    false,
        RestrictShare_:   true,
        RestrictView_:    false,
        SharedFolderKeys: make([]*SyncDownSharedFolderKey, 0),
      }
      if sfKeys != nil {
        for sfUid, sfKey := range sfKeys {
          key, _ = auth.EncryptAesV1(sfKey, teamKey)
          sdsfk := &SyncDownSharedFolderKey{
            SharedFolderUid_: sfUid,
            SharedFolderKey_: auth.Base64UrlEncode(key),
            KeyType_:         1,
          }
          sdt.SharedFolderKeys = append(sdt.SharedFolderKeys, sdsfk)
        }
      }
    }
  }
  return
}

func (am *authMock) registerUserFolder(userFolder *Folder) (sduf *SyncDownUserFolder) {
  var key = auth.GenerateAesKey()
  var data = make(map[string]interface{})
  data["name"] = userFolder.Name
  jData, _ := json.Marshal(&data)
  jData, _ = auth.EncryptAesV1(jData, am.AuthContext().DataKey())
  sduf = &SyncDownUserFolder{
    SyncDownFolderNode: SyncDownFolderNode{
      FolderUid_: userFolder.FolderUid,
    },
    FolderType_:    "user_folder",
    ParentUid_:     userFolder.ParentUid,
    UserFolderKey_: auth.Base64UrlEncode(key),
    KeyType_:       1,
    Data_:          auth.Base64UrlEncode(jData),
  }

  return
}

func (am *authMock) Close() error {
  return nil
}
func (am *authMock) Endpoint() auth.IKeeperEndpoint {
  return nil
}
func (am *authMock) AuthContext() auth.IAuthContext {
  return am.context
}
func (am *authMock) PushNotifications() auth.IPushEndpoint {
  return am.push
}
func (am *authMock) ExecuteAuthCommand(rq interface{}, rs interface{}, _ bool) (err error) {
  var ok bool
  var toCmd auth.ToKeeperApiCommand
  if toCmd, ok = rq.(auth.ToKeeperApiCommand); ok {
    apiRq := toCmd.GetKeeperApiCommand()
    if apiRq.Command == "" {
      var cmdName auth.ICommand
      if cmdName, ok = rq.(auth.ICommand); ok {
        apiRq.Command = cmdName.Command()
      }
    }
  }
  switch command := rq.(type) {
  case *SyncDownCommand:
    if response, ok := rs.(*SyncDownResponse); ok {
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

func (am *authMock) ExecuteRest(endpoint string, request proto.Message, response proto.Message) (err error) {
  return errors.New("not implemented")
}
func (am *authMock) ExecuteV2Command(interface{}, interface{}) (err error) {
  err = errors.New("not implemented")
  return
}
func (am *authMock) ExecuteAuthRest(string, proto.Message, proto.Message) (err error) {
  err = errors.New("not implemented")
  return
}
func (am *authMock) IsAuthenticated() bool {
  return true
}
func (am *authMock) Logout() {}

func (a *authMock) UiCallback() auth.IAuthUiCallback {
  return a.uiCallback
}
func (a *authMock) SetUiCallback(value auth.IAuthUiCallback) {
  a.uiCallback = value
}
