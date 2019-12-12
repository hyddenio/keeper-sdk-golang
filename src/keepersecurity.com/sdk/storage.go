// Copyright 2019 Keeper Security Inc. All rights reserved.

package sdk

type StorageKeyType int32
const (
	NoRecordKey StorageKeyType = 0
	UserClientKey = 1
	UserPublicKey = 2
	SharedFolderKey = 3
	TeamKey = 4
)

// IUid is the base interface for all entities
type IUid interface {
	Uid() string
}

// IUidLink is the base interface for all entity links
type IUidLink interface {
	SubjectUid() string
	ObjectUid() string
}

type CommonEntityStorage interface {
	Delete(string)
	Clear()
}
type BaseEntityStorage interface {
	get(string) IUid
	put(IUid)
	enumerate(func (IUid) bool)
}

type CommonLinkStorage interface {
	DeleteLink(IUidLink)
	Delete(string, string)
	DeleteObject(string)
	DeleteSubject(string)
	Clear()
}
type BaseLinkStorage interface {
	put(IUidLink)
	getLink(string, string) IUidLink
	getLinksForSubject(string, func (IUidLink) bool)
	getLinksForObject(string, func (IUidLink) bool)
	getAllLinks(func (IUidLink) bool)
}

type StorageRecord interface {
	RecordUid() string
	Revision() int64
	ClientModifiedTime() int64
	Data() string
	Extra() string
	UData() string
	Shared() bool
	Owner() bool
	SetOwner(value bool)
	IUid
}

type StorageNonSharedData interface {
	RecordUid() string
	Data() string
	IUid
}

type StorageSharedFolder interface {
	SharedFolderUid() string
	Revision() int64
	Name() string
	DefaultManageRecords() bool
	DefaultManageUsers() bool
	DefaultCanEdit() bool
	DefaultCanShare() bool
	IUid
}

type StorageTeam interface {
	TeamUid() string
	Name() string
	TeamPrivateKey() string
	RestrictEdit() bool
	RestrictShare() bool
	RestrictView() bool
	IUid
}

type StorageFolder interface {
	FolderUid() string
	SharedFolderUid() string
	ParentUid() string
	FolderType() string
	FolderKey() string
	Data() string
	IUid
}

type StorageRecordKey interface {
	RecordUid() string
	EncryptorUid() string
	KeyType() int32
	RecordKey() string
	CanShare() bool
	CanEdit() bool
	IUidLink
}

type StorageSharedFolderKey interface {
	SharedFolderUid() string
	EncryptorUid() string
	KeyType() int32
	SharedFolderKey() string
	IUidLink
}

type StorageSharedFolderPermission interface {
	SharedFolderUid() string
	UserId() string
	UserType() int
	ManageRecords() bool
	ManageUsers() bool
	IUidLink
}

type StorageTeamKey interface {
	TeamUid() string
	EncryptorUid() string
	KeyType() int32
	TeamKey() string
	IUidLink
}

type StorageFolderRecord interface {
	FolderUid() string
	RecordUid() string
	IUidLink
}

type RecordEntityStorage interface {
	Get(string) StorageRecord
	Put(StorageRecord)
	Enumerate(func (StorageRecord) bool)
	CommonEntityStorage
}
type SharedFolderEntityStorage interface {
	Get(string) StorageSharedFolder
	Put(StorageSharedFolder)
	Enumerate(func (StorageSharedFolder) bool)
	CommonEntityStorage
}

type TeamEntityStorage interface {
	Get(string) StorageTeam
	Put(StorageTeam)
	Enumerate(func (StorageTeam) bool)
	CommonEntityStorage
}

type FolderEntityStorage interface {
	Get(string) StorageFolder
	Put(StorageFolder)
	Enumerate(func (StorageFolder) bool)
	CommonEntityStorage
}

type NonSharedDataEntityStorage interface {
	Get(string) StorageNonSharedData
	Put(StorageNonSharedData)
	Enumerate(func (StorageNonSharedData) bool)
	CommonEntityStorage
}

type RecordKeysStorage interface {
	Put(StorageRecordKey)
	GetLink(string, string) StorageRecordKey
	GetLinksForSubject(string, func (StorageRecordKey) bool)
	GetLinksForObject(string, func (StorageRecordKey) bool)
	GetAllLinks(func (StorageRecordKey) bool)
	CommonLinkStorage
}
type SharedFolderKeysStorage interface {
	Put(StorageSharedFolderKey)
	GetLinksForSubject(string, func (StorageSharedFolderKey) bool)
	GetLinksForObject(string, func (StorageSharedFolderKey) bool)
	GetAllLinks(func (StorageSharedFolderKey) bool)
	CommonLinkStorage
}
type SharedFolderPermissionsStorage interface {
	Put(StorageSharedFolderPermission)
	GetLinksForSubject(string, func (StorageSharedFolderPermission) bool)
	GetLinksForObject(string, func (StorageSharedFolderPermission) bool)
	GetAllLinks(func (StorageSharedFolderPermission) bool)
	CommonLinkStorage
}

type TeamKeysStorage interface {
	Put(StorageTeamKey)
	GetLinksForSubject(string, func (StorageTeamKey) bool)
	GetLinksForObject(string, func (StorageTeamKey) bool)
	GetAllLinks(func (StorageTeamKey) bool)
	CommonLinkStorage
}

type FolderRecordsStorage interface {
	Put(StorageFolderRecord)
	GetLinksForSubject(string, func (StorageFolderRecord) bool)
	GetLinksForObject(string, func (StorageFolderRecord) bool)
	GetAllLinks(func (StorageFolderRecord) bool)
	CommonLinkStorage
}

type VaultStorage interface {
	PersonalScopeUid() string
	Revision() int64
	SetRevision(value int64)
	Clear()

	Records() RecordEntityStorage
	SharedFolders() SharedFolderEntityStorage
	Teams() TeamEntityStorage
	NonSharedData() NonSharedDataEntityStorage
	Folders() FolderEntityStorage

	RecordKeys() RecordKeysStorage
	SharedFolderKeys() SharedFolderKeysStorage
	SharedFolderPermissions() SharedFolderPermissionsStorage
	TeamKeys() TeamKeysStorage
	FolderRecords() FolderRecordsStorage
}

type UidLink struct {
	subjectUid string
	objectUid string
}
func (link *UidLink) SubjectUid() string {
	return link.subjectUid
}
func (link *UidLink) ObjectUid() string {
	return link.objectUid
}

func NewInMemoryVaultStorage() VaultStorage {
	var storage VaultStorage = new(inMemoryKeeperStorage)
	storage.Clear()
	return storage
}
