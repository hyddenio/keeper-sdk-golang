package vault

import "github.com/keeper-security/keeper-sdk-golang/sdk/storage"

type StorageKeyType int32

const (
	StorageKeyType_UserDataKey       StorageKeyType = 1 // AES GSM: user client key
	StorageKeyType_UserRsaPrivateKey                = 2 // RSA: user RSA key
	StorageKeyType_UserEcPrivateKey                 = 3
	StorageKeyType_SharedFolderKey                  = 4
	StorageKeyType_TeamKey                          = 5
	StorageKeyType_TeamRsaPrivateKey                = 6
	StorageKeyType_RecordKey                        = 7
)

type IStorageRecord interface {
	RecordUid() string
	Revision() int64
	Version() int32
	ClientModifiedTime() int64
	Data() []byte
	Extra() []byte
	UData() []byte
	Shared() bool
	Owner() bool
	SetOwner(value bool)
	OwnerAccountUid() string
	storage.IUid
}

type IStorageNonSharedData interface {
	RecordUid() string
	Data() []byte
	storage.IUid
}

type IStorageSharedFolder interface {
	SharedFolderUid() string
	Revision() int64
	Name() []byte
	Data() []byte
	DefaultManageRecords() bool
	DefaultManageUsers() bool
	DefaultCanEdit() bool
	DefaultCanShare() bool
	OwnerAccountUid() string
	storage.IUid
}

type IStorageTeam interface {
	TeamUid() string
	Name() string
	TeamKey() []byte
	KeyType() StorageKeyType
	TeamPrivateKey() []byte
	RestrictEdit() bool
	RestrictShare() bool
	RestrictView() bool
	storage.IUid
}

type IStorageFolder interface {
	FolderUid() string
	ParentUid() string
	SharedFolderUid() string
	FolderType() string
	FolderKey() []byte
	Data() []byte
	Revision() int64
	storage.IUid
}

type IStorageUserEmail interface {
	AccountUid() string
	Email() string
	storage.IUidLink[string, string]
}

type IStorageRecordKey interface {
	RecordUid() string
	EncryptorUid() string
	KeyType() StorageKeyType
	RecordKey() []byte
	CanShare() bool
	CanEdit() bool
	OwnerAccountUid() string
	storage.IUidLink[string, string]
}

type IStorageSharedFolderKey interface {
	SharedFolderUid() string
	EncryptorUid() string
	KeyType() StorageKeyType
	SharedFolderKey() []byte
	storage.IUidLink[string, string]
}

type SharedFolderUserType int32

const (
	SharedFolderUserType_User SharedFolderUserType = 1
	SharedFolderUserType_Team                      = 2
)

type IStorageSharedFolderPermission interface {
	SharedFolderUid() string
	UserId() string
	UserType() SharedFolderUserType
	ManageRecords() bool
	ManageUsers() bool
	Expiration() int64
	storage.IUidLink[string, string]
}

type IStorageFolderRecord interface {
	FolderUid() string
	RecordUid() string
	storage.IUidLink[string, string]
}

type IStorageBreachWatchRecord interface {
	RecordUid() string
	Data() []byte
	Type() int32
	Revision() int64
	storage.IUid
}

type RecordTypeScope int32

const (
	RecordTypeScope_Standard   RecordTypeScope = 0
	RecordTypeScope_User                       = 1
	RecordTypeScope_Enterprise                 = 2
)

type IStorageRecordType interface {
	Name() string
	Id() int
	Scope() RecordTypeScope
	Content() string
	storage.IUid
}

type IVaultStorage interface {
	PersonalScopeUid() []byte
	ContinuationToken() []byte
	SetContinuationToken([]byte)

	Records() storage.IEntityStorage[IStorageRecord, string]
	RecordTypes() storage.IEntityStorage[IStorageRecordType, string]
	SharedFolders() storage.IEntityStorage[IStorageSharedFolder, string]
	Teams() storage.IEntityStorage[IStorageTeam, string]
	UserEmails() storage.ILinkStorage[IStorageUserEmail, string, string]
	NonSharedData() storage.IEntityStorage[IStorageNonSharedData, string]
	RecordKeys() storage.ILinkStorage[IStorageRecordKey, string, string]
	SharedFolderKeys() storage.ILinkStorage[IStorageSharedFolderKey, string, string]
	SharedFolderPermissions() storage.ILinkStorage[IStorageSharedFolderPermission, string, string]
	Folders() storage.IEntityStorage[IStorageFolder, string]
	FolderRecords() storage.ILinkStorage[IStorageFolderRecord, string, string]
	BreachWatchRecords() storage.IEntityStorage[IStorageBreachWatchRecord, string]

	Clear()
}
