package sqldb

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"

	"keepersecurity.com/sdk/vault"
)

type recordKeyStorage struct {
	RecordUid_    string         `sdk:"record_uid,subject"`
	EncryptorUid_ string         `sdk:"encryptor_uid,object"`
	KeyType_      sql.NullInt32  `sdk:"key_type"`
	RecordKey_    sql.NullString `sdk:"record_key,400"`
	CanShare_     sql.NullBool   `sdk:"can_share"`
	CanEdit_      sql.NullBool   `sdk:"can_edit"`
}

func (rk *recordKeyStorage) RecordUid() string {
	return rk.RecordUid_
}
func (rk *recordKeyStorage) EncryptorUid() string {
	return rk.EncryptorUid_
}
func (rk *recordKeyStorage) KeyType() (kt int32) {
	if rk.KeyType_.Valid {
		kt = rk.KeyType_.Int32
	}
	return
}
func (rk *recordKeyStorage) RecordKey() (key string) {
	if rk.RecordKey_.Valid {
		key = rk.RecordKey_.String
	}
	return
}
func (rk *recordKeyStorage) CanShare() (b bool) {
	if rk.CanShare_.Valid {
		b = rk.CanShare_.Bool
	}
	return
}
func (rk *recordKeyStorage) CanEdit() (b bool) {
	if rk.CanEdit_.Valid {
		b = rk.CanEdit_.Bool
	}
	return
}
func (rk *recordKeyStorage) SubjectUid() string {
	return rk.RecordUid()
}
func (rk *recordKeyStorage) ObjectUid() string {
	return rk.EncryptorUid()
}
func (rk *recordKeyStorage) Initialize(recordKey vault.IStorageRecordKey) {
	rk.RecordUid_ = recordKey.RecordUid()
	rk.EncryptorUid_ = recordKey.EncryptorUid()
	rk.KeyType_ = sql.NullInt32{Int32: recordKey.KeyType(), Valid: true}
	rk.RecordKey_ = sql.NullString{String: recordKey.RecordKey(), Valid: true}
	rk.CanEdit_ = sql.NullBool{Bool: recordKey.CanEdit(), Valid: true}
	rk.CanShare_ = sql.NullBool{Bool: recordKey.CanShare(), Valid: true}
}
func (rk *recordKeyStorage) Init(source interface{}) (err error) {
	if recordKey, ok := source.(vault.IStorageRecordKey); ok {
		rk.Initialize(recordKey)
	} else {
		err = errors.New(fmt.Sprintf("invalid type. Expected: IStorageRecord, Got: %s", reflect.TypeOf(source).Name()))
	}
	return
}

type sharedFolderKeyStorage struct {
	SharedFolderUid_ string         `sdk:"shared_folder_uid,subject"`
	EncryptorUid_    string         `sdk:"encryptor_uid,object"`
	KeyType_         sql.NullInt32  `sdk:"key_type"`
	SharedFolderKey_ sql.NullString `sdk:"shared_folder_key,400"`
}

func (sfk *sharedFolderKeyStorage) SharedFolderUid() string {
	return sfk.SharedFolderUid_
}
func (sfk *sharedFolderKeyStorage) EncryptorUid() string {
	return sfk.EncryptorUid_
}
func (sfk *sharedFolderKeyStorage) KeyType() (kt int32) {
	if sfk.KeyType_.Valid {
		kt = sfk.KeyType_.Int32
	}
	return
}
func (sfk *sharedFolderKeyStorage) SharedFolderKey() (key string) {
	if sfk.SharedFolderKey_.Valid {
		key = sfk.SharedFolderKey_.String
	}
	return
}
func (sfk *sharedFolderKeyStorage) SubjectUid() string {
	return sfk.SharedFolderUid()
}
func (sfk *sharedFolderKeyStorage) ObjectUid() string {
	return sfk.EncryptorUid()
}
func (sfk *sharedFolderKeyStorage) Initialize(recordKey vault.IStorageSharedFolderKey) {
	sfk.SharedFolderUid_ = recordKey.SharedFolderUid()
	sfk.EncryptorUid_ = recordKey.EncryptorUid()
	sfk.KeyType_ = sql.NullInt32{Int32: recordKey.KeyType(), Valid: true}
	sfk.SharedFolderKey_ = sql.NullString{String: recordKey.SharedFolderKey(), Valid: true}
}
func (sfk *sharedFolderKeyStorage) Init(source interface{}) (err error) {
	if sharedFolderKey, ok := source.(vault.IStorageSharedFolderKey); ok {
		sfk.Initialize(sharedFolderKey)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageSharedFolderKey", reflect.TypeOf(source).Name()))
	}
	return
}

type sharedFolderPermissionStorage struct {
	SharedFolderUid_ string        `sdk:"shared_folder_uid,subject"`
	UserId_          string        `sdk:"user_id,object"`
	UserType_        sql.NullInt32 `sdk:"key_type"`
	ManageRecords_   sql.NullBool  `sdk:"manage_records"`
	ManageUsers_     sql.NullBool  `sdk:"manage_users"`
}

func (sfp *sharedFolderPermissionStorage) SharedFolderUid() string {
	return sfp.SharedFolderUid_
}
func (sfp *sharedFolderPermissionStorage) UserId() string {
	return sfp.UserId_
}
func (sfp *sharedFolderPermissionStorage) UserType() (ut int32) {
	if sfp.UserType_.Valid {
		ut = sfp.UserType_.Int32
	}
	return
}
func (sfp *sharedFolderPermissionStorage) ManageRecords() (b bool) {
	if sfp.ManageRecords_.Valid {
		b = sfp.ManageRecords_.Bool
	}
	return
}
func (sfp *sharedFolderPermissionStorage) ManageUsers() (b bool) {
	if sfp.ManageUsers_.Valid {
		b = sfp.ManageUsers_.Bool
	}
	return
}
func (sfp *sharedFolderPermissionStorage) SubjectUid() string {
	return sfp.SharedFolderUid()
}
func (sfp *sharedFolderPermissionStorage) ObjectUid() string {
	return sfp.UserId()
}
func (sfp *sharedFolderPermissionStorage) Initialize(permission vault.IStorageSharedFolderPermission) {
	sfp.SharedFolderUid_ = permission.SharedFolderUid()
	sfp.UserId_ = permission.UserId()
	sfp.UserType_ = sql.NullInt32{Int32: permission.UserType(), Valid: true}
	sfp.ManageRecords_ = sql.NullBool{Bool: permission.ManageRecords(), Valid: true}
	sfp.ManageUsers_ = sql.NullBool{Bool: permission.ManageUsers(), Valid: true}
}
func (sfp *sharedFolderPermissionStorage) Init(source interface{}) (err error) {
	if permission, ok := source.(vault.IStorageSharedFolderPermission); ok {
		sfp.Initialize(permission)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageSharedFolderPermission", reflect.TypeOf(source).Name()))
	}
	return
}

type teamKeyStorage struct {
	TeamUid_      string         `sdk:"team_uid,subject"`
	EncryptorUid_ string         `sdk:"encryptor_uid,object"`
	KeyType_      sql.NullInt32  `sdk:"key_type"`
	TeamKey_      sql.NullString `sdk:"team_key,400"`
}

func (tk *teamKeyStorage) TeamUid() string {
	return tk.TeamUid_
}
func (tk *teamKeyStorage) EncryptorUid() string {
	return tk.EncryptorUid_
}
func (tk *teamKeyStorage) KeyType() (kt int32) {
	if tk.KeyType_.Valid {
		kt = tk.KeyType_.Int32
	}
	return
}
func (tk *teamKeyStorage) TeamKey() (key string) {
	if tk.TeamKey_.Valid {
		key = tk.TeamKey_.String
	}
	return
}
func (tk *teamKeyStorage) SubjectUid() string {
	return tk.TeamUid()
}
func (tk *teamKeyStorage) ObjectUid() string {
	return tk.EncryptorUid()
}
func (tk *teamKeyStorage) Initialize(teamKey vault.IStorageTeamKey) {
	tk.TeamUid_ = teamKey.TeamUid()
	tk.EncryptorUid_ = teamKey.EncryptorUid()
	tk.KeyType_ = sql.NullInt32{Int32: teamKey.KeyType(), Valid: true}
	tk.TeamKey_ = sql.NullString{String: teamKey.TeamKey(), Valid: true}
}
func (tk *teamKeyStorage) Init(source interface{}) (err error) {
	if teamKey, ok := source.(vault.IStorageTeamKey); ok {
		tk.Initialize(teamKey)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageTeamKey", reflect.TypeOf(source).Name()))
	}
	return
}

type folderRecordStorage struct {
	FolderUid_ string `sdk:"folder_uid,subject"`
	RecordUid_ string `sdk:"record_uid,object"`
}

func (fr *folderRecordStorage) FolderUid() string {
	return fr.FolderUid_
}
func (fr *folderRecordStorage) RecordUid() string {
	return fr.RecordUid_
}
func (fr *folderRecordStorage) SubjectUid() string {
	return fr.FolderUid()
}
func (fr *folderRecordStorage) ObjectUid() string {
	return fr.RecordUid()
}
func (fr *folderRecordStorage) Initialize(folderRecord vault.IStorageFolderRecord) {
	fr.FolderUid_ = folderRecord.FolderUid()
	fr.RecordUid_ = folderRecord.RecordUid()
}
func (fr *folderRecordStorage) Init(source interface{}) (err error) {
	if folderRecord, ok := source.(vault.IStorageFolderRecord); ok {
		fr.Initialize(folderRecord)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageFolderRecord", reflect.TypeOf(source).Name()))
	}
	return
}
