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

type ITransaction interface {
	Begin() error
	Commit() error
	Rollback() error
	IsInTransaction() bool
}

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
type GenericEntityStorage interface {
	CommonEntityStorage
	GetEntity(string) IUid
	PutEntity(IUid)
	EnumerateEntities(func (IUid) bool)
}

type CommonLinkStorage interface {
	Delete(string, string)
	DeleteObject(string)
	DeleteSubject(string)
	Clear()
}
type GenericLinkStorage interface {
	CommonLinkStorage
	PutLink(IUidLink)
	GetLink(string, string) IUidLink
	GetLinksForSubject(string, func (IUidLink) bool)
	GetLinksForObject(string, func (IUidLink) bool)
	GetAllLinks(func (IUidLink) bool)
}

type IStorageRecord interface {
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

type IStorageNonSharedData interface {
	RecordUid() string
	Data() string
	IUid
}

type IStorageSharedFolder interface {
	SharedFolderUid() string
	Revision() int64
	Name() string
	DefaultManageRecords() bool
	DefaultManageUsers() bool
	DefaultCanEdit() bool
	DefaultCanShare() bool
	IUid
}

type IStorageTeam interface {
	TeamUid() string
	Name() string
	TeamPrivateKey() string
	RestrictEdit() bool
	RestrictShare() bool
	RestrictView() bool
	IUid
}

type IStorageFolder interface {
	FolderUid() string
	SharedFolderUid() string
	ParentUid() string
	FolderType() string
	FolderKey() string
	Data() string
	IUid
}

type IStorageRecordKey interface {
	RecordUid() string
	EncryptorUid() string
	KeyType() int32
	RecordKey() string
	CanShare() bool
	CanEdit() bool
	IUidLink
}

type IStorageSharedFolderKey interface {
	SharedFolderUid() string
	EncryptorUid() string
	KeyType() int32
	SharedFolderKey() string
	IUidLink
}

type IStorageSharedFolderPermission interface {
	SharedFolderUid() string
	UserId() string
	UserType() int32
	ManageRecords() bool
	ManageUsers() bool
	IUidLink
}

type IStorageTeamKey interface {
	TeamUid() string
	EncryptorUid() string
	KeyType() int32
	TeamKey() string
	IUidLink
}

type IStorageFolderRecord interface {
	FolderUid() string
	RecordUid() string
	IUidLink
}

type IRecordEntityStorage interface {
	Get(string) IStorageRecord
	Put(IStorageRecord)
	Enumerate(func (IStorageRecord) bool)
	CommonEntityStorage
}
type ISharedFolderEntityStorage interface {
	Get(string) IStorageSharedFolder
	Put(IStorageSharedFolder)
	Enumerate(func (IStorageSharedFolder) bool)
	CommonEntityStorage
}

type ITeamEntityStorage interface {
	Get(string) IStorageTeam
	Put(IStorageTeam)
	Enumerate(func (IStorageTeam) bool)
	CommonEntityStorage
}

type IFolderEntityStorage interface {
	Get(string) IStorageFolder
	Put(IStorageFolder)
	Enumerate(func (IStorageFolder) bool)
	CommonEntityStorage
}

type INonSharedDataEntityStorage interface {
	Get(string) IStorageNonSharedData
	Put(IStorageNonSharedData)
	Enumerate(func (IStorageNonSharedData) bool)
	CommonEntityStorage
}

type IRecordKeysStorage interface {
	Put(IStorageRecordKey)
	GetLink(string, string) IStorageRecordKey
	GetLinksForSubject(string, func (IStorageRecordKey) bool)
	GetLinksForObject(string, func (IStorageRecordKey) bool)
	GetAllLinks(func (IStorageRecordKey) bool)
	CommonLinkStorage
}
type ISharedFolderKeysStorage interface {
	Put(IStorageSharedFolderKey)
	GetLinksForSubject(string, func (IStorageSharedFolderKey) bool)
	GetLinksForObject(string, func (IStorageSharedFolderKey) bool)
	GetAllLinks(func (IStorageSharedFolderKey) bool)
	CommonLinkStorage
}
type ISharedFolderPermissionsStorage interface {
	Put(IStorageSharedFolderPermission)
	GetLinksForSubject(string, func (IStorageSharedFolderPermission) bool)
	GetLinksForObject(string, func (IStorageSharedFolderPermission) bool)
	GetAllLinks(func (IStorageSharedFolderPermission) bool)
	CommonLinkStorage
}

type ITeamKeysStorage interface {
	Put(IStorageTeamKey)
	GetLinksForSubject(string, func (IStorageTeamKey) bool)
	GetLinksForObject(string, func (IStorageTeamKey) bool)
	GetAllLinks(func (IStorageTeamKey) bool)
	CommonLinkStorage
}

type IFolderRecordsStorage interface {
	Put(IStorageFolderRecord)
	GetLinksForSubject(string, func (IStorageFolderRecord) bool)
	GetLinksForObject(string, func (IStorageFolderRecord) bool)
	GetAllLinks(func (IStorageFolderRecord) bool)
	CommonLinkStorage
}

type IVaultStorage interface {
	PersonalScopeUid() string
	Revision() int64
	SetRevision(value int64)
	Clear()

	Records() IRecordEntityStorage
	SharedFolders() ISharedFolderEntityStorage
	Teams() ITeamEntityStorage
	NonSharedData() INonSharedDataEntityStorage
	Folders() IFolderEntityStorage

	RecordKeys() IRecordKeysStorage
	SharedFolderKeys() ISharedFolderKeysStorage
	SharedFolderPermissions() ISharedFolderPermissionsStorage
	TeamKeys() ITeamKeysStorage
	FolderRecords() IFolderRecordsStorage
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
