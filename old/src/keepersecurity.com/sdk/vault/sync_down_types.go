package vault

import (
	"keepersecurity.com/sdk/auth"
)

type SyncDownCommand struct {
	auth.AuthorizedCommand
	Revision   int64    `json:"revision"`
	Include    []string `json:"include"`
	DeviceId   string   `json:"device_id"`
	DeviceName string   `json:"device_name"`
	ClientTime int64    `json:"client_time"`
}

func (c *SyncDownCommand) Command() string {
	return "sync_down"
}

type SyncDownResponse struct {
	auth.KeeperApiResponse
	FullSync                         bool                                    `json:"full_sync"`
	Revision                         int64                                   `json:"revision"`
	Records                          []*SyncDownRecord                       `json:"records"`
	SharedFolders                    []*SyncDownSharedFolder                 `json:"shared_folders"`
	Teams                            []*SyncDownTeam                         `json:"teams"`
	NonSharedData                    []*SyncDownNonSharedData                `json:"non_shared_data"`
	RecordMetaData                   []*SyncDownRecordMetaData               `json:"record_meta_data"`
	RemovedRecords                   []string                                `json:"removed_records"`
	RemovedSharedFolders             []string                                `json:"removed_shared_folders"`
	RemovedTeams                     []string                                `json:"removed_teams"`
	SharingChanges                   []*SyncDownSharingChanges               `json:"sharing_changes"`
	PendingSharesFrom                []string                                `json:"pending_shares_from"`
	UserFolders                      []*SyncDownUserFolder                   `json:"user_folders"`
	UserFolderRecords                []*SyncDownFolderRecordNode             `json:"user_folder_records"`
	UserFoldersRemoved               []*SyncDownFolderNode                   `json:"user_folders_removed"`
	UserFoldersRemovedRecords        []*SyncDownFolderRecordNode             `json:"user_folders_removed_records"`
	UserFolderSharedFolders          []*SyncDownUserFolderSharedFolder       `json:"user_folder_shared_folders"`
	UserFolderSharedFoldersRemoved   []*SyncDownUserFolderSharedFolder       `json:"user_folder_shared_folders_removed"`
	SharedFolderFolders              []*SyncDownSharedFolderFolder           `json:"shared_folder_folders"`
	SharedFolderFolderRemoved        []*SyncDownSharedFolderFolderNode       `json:"shared_folder_folder_removed"`
	SharedFolderFolderRecords        []*SyncDownSharedFolderFolderRecordNode `json:"shared_folder_folder_records"`
	SharedFolderFolderRecordsRemoved []*SyncDownSharedFolderFolderRecordNode `json:"shared_folder_folder_records_removed"`
}

type SyncDownRecord struct {
	RecordUid_          string                 `json:"record_uid"`
	Revision_           int64                  `json:"revision"`
	Version_            int32                  `json:"version"`
	ClientModifiedTime_ int64                  `json:"client_modified_time"`
	Shared_             bool                   `json:"shared"`
	Data_               string                 `json:"data"`
	Extra_              string                 `json:"extra"`
	Udata_              map[string]interface{} `json:"udata"`
	owner               bool                   `json:"-"`
	udata               string                 `json:"-"`
}

type SyncDownSharedFolder struct {
	SharedFolderUid_      string                        `json:"shared_folder_uid"`
	Revision_             int64                         `json:"revision"`
	Name_                 string                        `json:"name"`
	SharedFolderKey       *string                       `json:"shared_folder_key"`
	KeyType               *int32                        `json:"key_type"`
	ManageRecords         *bool                         `json:"manage_records"`
	ManageUsers           *bool                         `json:"manage_users"`
	DefaultManageRecords_ bool                          `json:"default_manage_records"`
	DefaultManageUsers_   bool                          `json:"default_manage_users"`
	DefaultCanEdit_       bool                          `json:"default_can_edit"`
	DefaultCanShare_      bool                          `json:"default_can_share"`
	FullSync              bool                          `json:"full_sync"`
	Records               []*SyncDownSharedFolderRecord `json:"records"`
	Users                 []*SyncDownSharedFolderUser   `json:"users"`
	Teams                 []*SyncDownSharedFolderTeam   `json:"teams"`
	RecordsRemoved        []string                      `json:"records_removed"`
	UsersRemoved          []string                      `json:"users_removed"`
	TeamsRemoved          []string                      `json:"teams_removed"`
}

type SyncDownSharedFolderRecord struct {
	RecordUid_   string `json:"record_uid"`
	RecordKey_   string `json:"record_key"`
	CanShare_    bool   `json:"can_share"`
	CanEdit_     bool   `json:"can_edit"`
	encryptorUid string `json:"-"`
}

type SyncDownSharedFolderUser struct {
	Username        string `json:"username"`
	ManageRecords_  bool   `json:"manage_records"`
	ManageUsers_    bool   `json:"manage_users"`
	sharedFolderUid string `json:"-"`
}
type SyncDownSharedFolderTeam struct {
	TeamUid         string `json:"team_uid"`
	Name_           string `json:"name"`
	ManageRecords_  bool   `json:"manage_records"`
	ManageUsers_    bool   `json:"manage_users"`
	sharedFolderUid string `json:"-"`
}

type SyncDownTeam struct {
	TeamUid_             string                     `json:"team_uid"`
	Name_                string                     `json:"name"`
	TeamKey_             string                     `json:"team_key"`
	TeamKeyType_         int32                      `json:"team_key_type"`
	TeamPrivateKey_      string                     `json:"team_private_key"`
	RestrictEdit_        bool                       `json:"restrict_edit"`
	RestrictShare_       bool                       `json:"restrict_share"`
	RestrictView_        bool                       `json:"restrict_view"`
	RemovedSharedFolders []string                   `json:"removed_shared_folders"`
	SharedFolderKeys     []*SyncDownSharedFolderKey `json:"shared_folder_keys"`
	encryptorUid         string                     `json:"-"`
}

type SyncDownSharedFolderKey struct {
	SharedFolderUid_ string `json:"shared_folder_uid"`
	SharedFolderKey_ string `json:"shared_folder_key"`
	KeyType_         int32  `json:"key_type"`
	encryptorUid     string `json:"-"`
}

type SyncDownNonSharedData struct {
	RecordUid_ string `json:"record_uid"`
	Data_      string `json:"data"`
}
type SyncDownRecordMetaData struct {
	RecordUid_     string `json:"record_uid"`
	RecordKey_     string `json:"record_key"`
	RecordKeyType_ int32  `json:"record_key_type"`
	Owner          bool   `json:"owner"`
	CanShare_      bool   `json:"can_share"`
	CanEdit_       bool   `json:"can_edit"`
	encryptorUid   string `json:"-"`
}

type SyncDownSharingChanges struct {
	RecordUid string `json:"record_uid"`
	Shared    bool   `json:"shared"`
}

type SyncDownFolderNode struct {
	FolderUid_ string `json:"folder_uid"`
}

type SyncDownFolderRecordNode struct {
	SyncDownFolderNode
	RecordUid_ string `json:"record_uid"`
}

type SyncDownUserFolder struct {
	SyncDownFolderNode
	FolderType_    string `json:"type"`
	ParentUid_     string `json:"parent_uid"`
	UserFolderKey_ string `json:"user_folder_key"`
	KeyType_       int32  `json:"key_type"`
	Data_          string `json:"data"`
}

type SyncDownUserFolderSharedFolder struct {
	SyncDownFolderNode
	SharedFolderUid_ string `json:"shared_folder_uid"`
}

type SyncDownSharedFolderFolderNode struct {
	SyncDownFolderNode
	ParentUid_       string `json:"parent_uid"`
	SharedFolderUid_ string `json:"shared_folder_uid"`
}

type SyncDownSharedFolderFolder struct {
	SyncDownSharedFolderFolderNode
	FolderType_            string `json:"type"`
	SharedFolderFolderKey_ string `json:"shared_folder_folder_key"`
	Data_                  string `json:"data"`
}

type SyncDownSharedFolderFolderRecordNode struct {
	SyncDownFolderNode
	RecordUid_       string `json:"record_uid"`
	SharedFolderUid_ string `json:"shared_folder_uid"`
}
