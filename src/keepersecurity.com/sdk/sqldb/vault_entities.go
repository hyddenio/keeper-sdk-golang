package sqldb

import (
	"database/sql"
	"errors"
	"fmt"
	"keepersecurity.com/sdk"
	"reflect"
)

type recordStorage struct {
	RecordUid_  string         `sdk:"record_uid,uid"`
	Revision_   sql.NullInt64  `sdk:"revision"`
	ClientTime_ sql.NullInt64  `sdk:"client_time"`
	Data_       sql.NullString `sdk:"data"`
	Extra_      sql.NullString `sdk:"extra"`
	UData_      sql.NullString `sdk:"udata"`
	Shared_     sql.NullBool   `sdk:"shared"`
	Owner_      sql.NullBool   `sdk:"owner"`
}

// IStorageRecord
func (r *recordStorage) RecordUid() string {
	return r.RecordUid_
}
func (r *recordStorage) Revision() (revision int64) {
	if r.Revision_.Valid {
		revision = r.Revision_.Int64
	}
	return
}
func (r *recordStorage) ClientModifiedTime() (clientTime int64) {
	if r.ClientTime_.Valid {
		clientTime = r.ClientTime_.Int64
	}
	return
}
func (r *recordStorage) Data() (data string) {
	if r.Data_.Valid {
		data = r.Data_.String
	}
	return
}
func (r *recordStorage) Extra() (extra string) {
	if r.Extra_.Valid {
		extra = r.Extra_.String
	}
	return
}
func (r *recordStorage) UData() (udata string) {
	if r.UData_.Valid {
		udata = r.UData_.String
	}
	return
}
func (r *recordStorage) Shared() (shared bool) {
	if r.Shared_.Valid {
		shared = r.Shared_.Bool
	}
	return
}
func (r *recordStorage) Owner() (owner bool) {
	if r.Owner_.Valid {
		owner = r.Owner_.Bool
	}
	return
}
func (r *recordStorage) SetOwner(value bool) {
	r.Owner_ = sql.NullBool{Bool: value, Valid: true}
}
func (r *recordStorage) Uid() string {
	return r.RecordUid()
}
func (r *recordStorage) Initialize(record sdk.IStorageRecord) {
	r.RecordUid_ = record.RecordUid()
	r.Revision_ = sql.NullInt64{Int64: record.Revision(), Valid: true}
	r.ClientTime_ = sql.NullInt64{Int64: record.ClientModifiedTime(), Valid: true}
	r.Data_ = sql.NullString{String: record.Data(), Valid: true}
	r.Extra_ = sql.NullString{String: record.Extra(), Valid: true}
	r.UData_ = sql.NullString{String: record.UData(), Valid: true}
	r.Shared_ = sql.NullBool{Bool: record.Shared(), Valid: true}
	r.Owner_ = sql.NullBool{Bool: record.Owner(), Valid: true}
}
func (r *recordStorage) Init(source interface{}) (err error) {
	if record, ok := source.(sdk.IStorageRecord); ok {
		r.Initialize(record)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageRecord", reflect.TypeOf(source).Name()))
	}
	return
}

type nonSharedDataStorage struct {
	RecordUid_ string         `sdk:"record_uid,uid"`
	Data_      sql.NullString `sdk:"data"`
}
func (nsd *nonSharedDataStorage) RecordUid() string {
	return nsd.RecordUid_
}
func (nsd *nonSharedDataStorage) Data() (data string) {
	if nsd.Data_.Valid {
		data = nsd.Data_.String
	}
	return
}
func (nsd *nonSharedDataStorage) Uid() string {
	return nsd.RecordUid()
}
func (nsd *nonSharedDataStorage) Initialize(record sdk.IStorageNonSharedData) {
	nsd.RecordUid_ = record.RecordUid()
	nsd.Data_ = sql.NullString{String: record.Data(), Valid: true}
}
func (nsd *nonSharedDataStorage) Init(source interface{}) (err error) {
	if record, ok := source.(sdk.IStorageNonSharedData); ok {
		nsd.Initialize(record)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageNonSharedData", reflect.TypeOf(source).Name()))
	}
	return
}

type sharedFolderStorage struct {
	SharedFolderUid_ string         `sdk:"shared_folder_uid,uid"`
	Revision_        sql.NullInt64  `sdk:"revision"`
	Name_            sql.NullString `sdk:"name,64"`
	ManageRecords_   sql.NullBool   `sdk:"manage_records"`
	ManageUsers_     sql.NullBool   `sdk:"manage_users"`
	CanEdit_         sql.NullBool   `sdk:"can_edit"`
	CanShare_        sql.NullBool   `sdk:"can_share"`
}
func (sf *sharedFolderStorage) SharedFolderUid() string {
	return sf.SharedFolderUid_
}
func (sf *sharedFolderStorage) Revision() (revision int64) {
	if sf.Revision_.Valid {
		revision = sf.Revision_.Int64
	}
	return
}
func (sf *sharedFolderStorage) Name() (name string) {
	if sf.Name_.Valid {
		name = sf.Name_.String
	}
	return
}
func (sf *sharedFolderStorage) DefaultManageRecords() (b bool) {
	if sf.ManageRecords_.Valid {
		b = sf.ManageRecords_.Bool
	}
	return
}
func (sf *sharedFolderStorage) DefaultManageUsers() (b bool) {
	if sf.ManageUsers_.Valid {
		b = sf.ManageUsers_.Bool
	}
	return
}
func (sf *sharedFolderStorage) DefaultCanEdit() (b bool) {
	if sf.CanEdit_.Valid {
		b = sf.CanEdit_.Bool
	}
	return
}
func (sf *sharedFolderStorage) DefaultCanShare() (b bool) {
	if sf.CanShare_.Valid {
		b = sf.CanShare_.Bool
	}
	return
}
func (sf *sharedFolderStorage) Uid() string {
	return sf.SharedFolderUid()
}
func (sf *sharedFolderStorage) Initialize(record sdk.IStorageSharedFolder) {
	sf.SharedFolderUid_ = record.SharedFolderUid()
	sf.Revision_ = sql.NullInt64{Int64: record.Revision(), Valid: true}
	sf.Name_ = sql.NullString{String: record.Name(), Valid: true}
	sf.ManageRecords_ = sql.NullBool{Bool: record.DefaultManageRecords(), Valid: true}
	sf.ManageUsers_ = sql.NullBool{Bool: record.DefaultManageUsers(), Valid: true}
	sf.CanEdit_ = sql.NullBool{Bool: record.DefaultCanEdit(), Valid: true}
	sf.CanShare_ = sql.NullBool{Bool: record.DefaultCanShare(), Valid: true}
}
func (sf *sharedFolderStorage) Init(source interface{}) (err error) {
	if record, ok := source.(sdk.IStorageSharedFolder); ok {
		sf.Initialize(record)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageSharedFolder", reflect.TypeOf(source).Name()))
	}
	return
}

type teamStorage struct {
	TeamUid_        string         `sdk:"team_uid,uid"`
	Name_           sql.NullString `sdk:"name,64"`
	TeamPrivateKey_ sql.NullString `sdk:"team_private_key,400"`
	RestrictEdit_   sql.NullBool   `sdk:"restrict_edit"`
	RestrictShare_  sql.NullBool   `sdk:"restrict_share"`
	RestrictView_   sql.NullBool   `sdk:"restrict_view"`
}
func (t *teamStorage) TeamUid() string {
	return t.TeamUid_
}
func (t *teamStorage) Name() (name string) {
	if t.Name_.Valid {
		name = t.Name_.String
	}
	return
}
func (t *teamStorage) TeamPrivateKey() (tpk string) {
	if t.TeamPrivateKey_.Valid {
		tpk = t.TeamPrivateKey_.String
	}
	return
}
func (t *teamStorage) RestrictEdit() (b bool) {
	if t.RestrictEdit_.Valid {
		b= t.RestrictEdit_.Bool
	}
	return
}
func (t *teamStorage) RestrictShare() (b bool) {
	if t.RestrictShare_.Valid {
		b = t.RestrictShare_.Bool
	}
	return
}
func (t *teamStorage) RestrictView() (b bool) {
	if t.RestrictView_.Valid {
		b = t.RestrictView_.Bool
	}
	return
}
func (t *teamStorage) Uid() string {
	return t.TeamUid()
}
func (t *teamStorage) Initialize(team sdk.IStorageTeam) {
	t.TeamUid_ = team.TeamUid()
	t.Name_ = sql.NullString{String: team.Name(), Valid: true}
	t.TeamPrivateKey_ = sql.NullString{String: team.TeamPrivateKey(), Valid: true}
	t.RestrictEdit_ = sql.NullBool{Bool: team.RestrictEdit(), Valid: true}
	t.RestrictShare_ = sql.NullBool{Bool: team.RestrictShare(), Valid: true}
	t.RestrictView_ = sql.NullBool{Bool: team.RestrictView(), Valid: true}
}
func (t *teamStorage) Init(source interface{}) (err error) {
	if team, ok := source.(sdk.IStorageTeam); ok {
		t.Initialize(team)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageTeam", reflect.TypeOf(source).Name()))
	}
	return
}

type folderStorage struct {
	FolderUid_       string         `sdk:"folder_uid,uid"`
	SharedFolderUid_ sql.NullString `sdk:"shared_folder_uid,32"`
	ParentUid_       sql.NullString `sdk:"parent_uid,32"`
	FolderType_      sql.NullString `sdk:"folder_type,32"`
	FolderKey_       sql.NullString `sdk:"folder_key,64"`
	Data_            sql.NullString `sdk:"data"`
}
func (f *folderStorage) FolderUid() string {
	return f.FolderUid_
}
func (f *folderStorage) SharedFolderUid() (uid string) {
	if f.SharedFolderUid_.Valid {
		uid = f.SharedFolderUid_.String
	}
	return
}
func (f *folderStorage) ParentUid() (uid string) {
	if f.ParentUid_.Valid {
		uid = f.ParentUid_.String
	}
	return
}
func (f *folderStorage) FolderType() (ft string) {
	if f.FolderType_.Valid {
		ft = f.FolderType_.String
	}
	return
}
func (f *folderStorage) FolderKey() (fk string) {
	if f.FolderKey_.Valid {
		fk = f.FolderKey_.String
	}
	return
}
func (f *folderStorage) Data() (data string) {
	if f.Data_.Valid {
		data = f.Data_.String
	}
	return
}
func (f *folderStorage) Uid() string {
	return f.FolderUid()
}

func (f *folderStorage) Initialize(folder sdk.IStorageFolder) {
	f.FolderUid_ = folder.FolderUid()
	f.SharedFolderUid_ = sql.NullString{String: folder.SharedFolderUid(), Valid: true}
	f.ParentUid_ = sql.NullString{String: folder.ParentUid(), Valid: true}
	f.FolderType_ = sql.NullString{String: folder.FolderType(), Valid: true}
	f.FolderKey_ = sql.NullString{String: folder.FolderKey(), Valid: true}
	f.Data_ = sql.NullString{String: folder.Data(), Valid: true}
}
func (f *folderStorage) Init(source interface{}) (err error) {
	if folder, ok := source.(sdk.IStorageFolder); ok {
		f.Initialize(folder)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement IStorageFolder", reflect.TypeOf(source).Name()))
	}
	return
}
