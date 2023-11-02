package vault

var (
	_ IStorageRecord                 = &RecordStorage{}
	_ IStorageNonSharedData          = &NonSharedDataStorage{}
	_ IStorageSharedFolder           = &SharedFolderStorage{}
	_ IStorageTeam                   = &TeamStorage{}
	_ IStorageFolder                 = &FolderStorage{}
	_ IStorageRecordType             = &RecordTypeStorage{}
	_ IStorageUserEmail              = &UserEmailStorage{}
	_ IStorageRecordKey              = &RecordKeyStorage{}
	_ IStorageSharedFolderKey        = &SharedFolderKeyStorage{}
	_ IStorageSharedFolderPermission = &SharedFolderPermissionStorage{}
	_ IStorageFolderRecord           = &FolderRecordStorage{}
	_ IStorageBreachWatchRecord      = &BreachWatchRecordStorage{}
)

type RecordStorage struct {
	RecordUid_    string `db:"record_uid"`
	Revision_     int64  `db:"revision"`
	Version_      int32  `db:"version"`
	ClientTime_   int64  `db:"client_time"`
	Data_         []byte `db:"data"`
	Extra_        []byte `db:"extra"`
	UData_        []byte `db:"udata"`
	Shared_       bool   `db:"shared"`
	Owner_        bool   `db:"owner"`
	OwnerAccount_ string `db:"owner_account"`
}

func (r *RecordStorage) RecordUid() string {
	return r.RecordUid_
}
func (r *RecordStorage) Revision() int64 {
	return r.Revision_
}
func (r *RecordStorage) Version() int32 {
	return r.Version_
}
func (r *RecordStorage) ClientModifiedTime() int64 {
	return r.ClientTime_
}
func (r *RecordStorage) Data() []byte {
	return r.Data_
}
func (r *RecordStorage) Extra() []byte {
	return r.Extra_
}
func (r *RecordStorage) UData() []byte {
	return r.UData_
}
func (r *RecordStorage) Shared() bool {
	return r.Shared_
}
func (r *RecordStorage) Owner() bool {
	return r.Owner_
}
func (r *RecordStorage) SetOwner(value bool) {
	r.Owner_ = value
}
func (r *RecordStorage) OwnerAccountUid() string {
	return r.OwnerAccount_
}
func (r *RecordStorage) Uid() string {
	return r.RecordUid()
}

type NonSharedDataStorage struct {
	RecordUid_ string `db:"record_uid"`
	Data_      []byte `db:"data"`
}

func (nsd *NonSharedDataStorage) RecordUid() string {
	return nsd.RecordUid_
}
func (nsd *NonSharedDataStorage) Data() []byte {
	return nsd.Data_
}
func (nsd *NonSharedDataStorage) Uid() string {
	return nsd.RecordUid()
}

type SharedFolderStorage struct {
	SharedFolderUid_ string `db:"shared_folder_uid"`
	Revision_        int64  `db:"revision"`
	Name_            []byte `db:"name"`
	Data_            []byte `db:"data"`
	ManageRecords_   bool   `db:"manage_records"`
	ManageUsers_     bool   `db:"manage_users"`
	CanEdit_         bool   `db:"can_edit"`
	CanShare_        bool   `db:"can_share"`
	OwnerAccount_    string `db:"owner_account"`
}

func (sf *SharedFolderStorage) SharedFolderUid() string {
	return sf.SharedFolderUid_
}
func (sf *SharedFolderStorage) Revision() (revision int64) {
	return sf.Revision_
}
func (sf *SharedFolderStorage) Name() []byte {
	return sf.Name_
}
func (sf *SharedFolderStorage) Data() []byte {
	return sf.Data_
}
func (sf *SharedFolderStorage) DefaultManageRecords() bool {
	return sf.ManageRecords_
}
func (sf *SharedFolderStorage) DefaultManageUsers() bool {
	return sf.ManageUsers_
}
func (sf *SharedFolderStorage) DefaultCanEdit() bool {
	return sf.CanEdit_
}
func (sf *SharedFolderStorage) DefaultCanShare() bool {
	return sf.CanShare_
}
func (sf *SharedFolderStorage) OwnerAccountUid() string {
	return sf.OwnerAccount_
}
func (sf *SharedFolderStorage) Uid() string {
	return sf.SharedFolderUid()
}

type TeamStorage struct {
	TeamUid_       string `db:"team_uid"`
	Name_          string `db:"name"`
	TeamKey_       []byte `db:"team_key"`
	KeyType_       int32  `db:"key_type"`
	PrivateKey_    []byte `db:"team_private_key"`
	RestrictEdit_  bool   `db:"restrict_edit"`
	RestrictShare_ bool   `db:"restrict_share"`
	RestrictView_  bool   `db:"restrict_view"`
}

func (t *TeamStorage) TeamUid() string {
	return t.TeamUid_
}
func (t *TeamStorage) Name() string {
	return t.Name_
}
func (t *TeamStorage) TeamKey() []byte {
	return t.TeamKey_
}
func (t *TeamStorage) KeyType() StorageKeyType {
	return StorageKeyType(t.KeyType_)
}
func (t *TeamStorage) TeamPrivateKey() []byte {
	return t.PrivateKey_
}
func (t *TeamStorage) RestrictEdit() (b bool) {
	return t.RestrictEdit_
}
func (t *TeamStorage) RestrictShare() (b bool) {
	return t.RestrictShare_
}
func (t *TeamStorage) RestrictView() (b bool) {
	return t.RestrictView_
}
func (t *TeamStorage) Uid() string {
	return t.TeamUid()
}

type FolderStorage struct {
	FolderUid_       string `db:"folder_uid"`
	SharedFolderUid_ string `db:"shared_folder_uid"`
	ParentUid_       string `db:"parent_uid"`
	Revision_        int64  `db:"revision"`
	FolderType_      string `db:"folder_type"`
	FolderKey_       []byte `db:"folder_key"`
	Data_            []byte `db:"data"`
}

func (f *FolderStorage) FolderUid() string {
	return f.FolderUid_
}
func (f *FolderStorage) SharedFolderUid() string {
	return f.SharedFolderUid_
}
func (f *FolderStorage) ParentUid() string {
	return f.ParentUid_
}
func (f *FolderStorage) FolderType() string {
	return f.FolderType_
}
func (f *FolderStorage) Revision() int64 {
	return f.Revision_
}
func (f *FolderStorage) FolderKey() []byte {
	return f.FolderKey_
}
func (f *FolderStorage) Data() []byte {
	return f.Data_
}
func (f *FolderStorage) Uid() string {
	return f.FolderUid()
}

type RecordTypeStorage struct {
	Name_    string
	Id_      int
	Scope_   RecordTypeScope
	Content_ string
}

func (f *RecordTypeStorage) Name() string {
	return f.Name_
}
func (f *RecordTypeStorage) Id() int {
	return f.Id_
}
func (f *RecordTypeStorage) Scope() RecordTypeScope {
	return f.Scope_
}
func (f *RecordTypeStorage) Content() string {
	return f.Content_
}
func (f *RecordTypeStorage) Uid() string {
	return f.Name()
}

type UserEmailStorage struct {
	AccountUid_ string
	Email_      string
}

func (ues *UserEmailStorage) AccountUid() string {
	return ues.AccountUid_
}

func (ues *UserEmailStorage) Email() string {
	return ues.Email_
}
func (ues *UserEmailStorage) SubjectUid() string {
	return ues.AccountUid()
}
func (ues *UserEmailStorage) ObjectUid() string {
	return ues.Email()
}

type RecordKeyStorage struct {
	RecordUid_    string
	EncryptorUid_ string
	KeyType_      int32
	RecordKey_    []byte
	CanShare_     bool
	CanEdit_      bool
	OwnerAccount_ string
}

func (rks *RecordKeyStorage) RecordUid() string {
	return rks.RecordUid_
}
func (rks *RecordKeyStorage) EncryptorUid() string {
	return rks.EncryptorUid_
}
func (rks *RecordKeyStorage) KeyType() StorageKeyType {
	return StorageKeyType(rks.KeyType_)
}
func (rks *RecordKeyStorage) RecordKey() []byte {
	return rks.RecordKey_
}
func (rks *RecordKeyStorage) CanShare() bool {
	return rks.CanShare_
}
func (rks *RecordKeyStorage) CanEdit() bool {
	return rks.CanEdit_
}
func (rks *RecordKeyStorage) OwnerAccountUid() string {
	return rks.OwnerAccount_
}
func (rks *RecordKeyStorage) SubjectUid() string {
	return rks.RecordUid()
}
func (rks *RecordKeyStorage) ObjectUid() string {
	return rks.EncryptorUid()
}

type SharedFolderKeyStorage struct {
	SharedFolderUid_ string
	EncryptorUid_    string
	KeyType_         int32
	SharedFolderKey_ []byte
}

func (sfk *SharedFolderKeyStorage) SharedFolderUid() string {
	return sfk.SharedFolderUid_
}
func (sfk *SharedFolderKeyStorage) EncryptorUid() string {
	return sfk.EncryptorUid_
}
func (sfk *SharedFolderKeyStorage) KeyType() StorageKeyType {
	return StorageKeyType(sfk.KeyType_)
}
func (sfk *SharedFolderKeyStorage) SharedFolderKey() []byte {
	return sfk.SharedFolderKey_
}
func (sfk *SharedFolderKeyStorage) SubjectUid() string {
	return sfk.SharedFolderUid()
}
func (sfk *SharedFolderKeyStorage) ObjectUid() string {
	return sfk.EncryptorUid()
}

type SharedFolderPermissionStorage struct {
	SharedFolderUid_ string
	UserId_          string
	UserType_        int32
	ManageRecords_   bool
	ManageUsers_     bool
	Expiration_      int64
}

func (sfp *SharedFolderPermissionStorage) SharedFolderUid() string {
	return sfp.SharedFolderUid_
}
func (sfp *SharedFolderPermissionStorage) UserId() string {
	return sfp.UserId_
}
func (sfp *SharedFolderPermissionStorage) UserType() SharedFolderUserType {
	return SharedFolderUserType(sfp.UserType_)
}
func (sfp *SharedFolderPermissionStorage) ManageRecords() bool {
	return sfp.ManageRecords_
}
func (sfp *SharedFolderPermissionStorage) ManageUsers() bool {
	return sfp.ManageUsers_
}
func (sfp *SharedFolderPermissionStorage) Expiration() int64 {
	return sfp.Expiration_
}
func (sfp *SharedFolderPermissionStorage) SubjectUid() string {
	return sfp.SharedFolderUid()
}
func (sfp *SharedFolderPermissionStorage) ObjectUid() string {
	return sfp.UserId()
}

type FolderRecordStorage struct {
	FolderUid_ string
	RecordUid_ string
}

func (fr *FolderRecordStorage) FolderUid() string {
	return fr.FolderUid_
}
func (fr *FolderRecordStorage) RecordUid() string {
	return fr.RecordUid_
}
func (fr *FolderRecordStorage) SubjectUid() string {
	return fr.FolderUid()
}
func (fr *FolderRecordStorage) ObjectUid() string {
	return fr.RecordUid()
}

type BreachWatchRecordStorage struct {
	RecordUid_ string
	Data_      []byte
	Type_      int32
	Revision_  int64
}

func (bwr *BreachWatchRecordStorage) RecordUid() string {
	return bwr.RecordUid_
}
func (bwr *BreachWatchRecordStorage) Data() []byte {
	return bwr.Data_
}
func (bwr *BreachWatchRecordStorage) Type() int32 {
	return bwr.Type_
}
func (bwr *BreachWatchRecordStorage) Revision() int64 {
	return bwr.Revision_
}
func (bwr *BreachWatchRecordStorage) Uid() string {
	return bwr.RecordUid()
}
