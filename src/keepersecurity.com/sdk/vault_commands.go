package sdk

type RecordAddCommand struct {
	AuthorizedCommand
	RecordUid  string `json:"record_uid,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	RecordKey  string `json:"record_key,omitempty"`
	HowLongAgo int64  `json:"how_long_ago,omitempty"`
	FolderType string `json:"folder_type,omitempty"`
	FolderUid  string `json:"folder_uid,omitempty"`
	FolderKey  string `json:"folder_key,omitempty"`
	Data       string `json:"data,omitempty"`
	Extra      string `json:"extra,omitempty"`
	Udata      string `json:"udata,omitempty"`
}
func (c *RecordAddCommand) Command() string {
	return "record_add"
}

type RecordObject struct {
	RecordUid          string `json:"record_uid,omitempty"`
	SharedFolderUid    string `json:"shared_folder_uid,omitempty"`
	TeamUid            string `json:"team_uid,omitempty"`
	Version            int32  `json:"version,omitempty"`
	Revision           int64  `json:"revision,omitempty"`
	RecordKey          string `json:"record_key,omitempty"`
	ClientModifiedTime int64  `json:"client_modified_time,omitempty"`
	Data               string `json:"data,omitempty"`
	Extra              string `json:"extra,omitempty"`
	Udata              string `json:"udata,omitempty"`
	NonSharedData      string `json:"non_shared_data,omitempty"`
}

type RecordUpdateCommand struct {
	AuthorizedCommand
	Pt            string          `json:"pt,omitempty"`
	ClientTime    int64           `json:"client_time,omitempty"`
	AddRecords    []*RecordObject `json:"add_records,omitempty"`
	UpdateRecords []*RecordObject `json:"update_records,omitempty"`
	RemoveRecords []string        `json:"remove_records,omitempty"`
	DeleteRecords []string        `json:"delete_records,omitempty"`
}

func (c *RecordUpdateCommand) Command() string {
	return "record_update"
}

type StatusObject struct {
	RecordUid string `json:"record_uid,omitempty"`
	Status    string `json:"status,omitempty"`
}

type RecordUpdateResponse struct {
	KeeperApiResponse
	AddRecords    []*StatusObject `json:"add_records,omitempty"`
	UpdateRecords []*StatusObject `json:"update_records,omitempty"`
	RemoveRecords []*StatusObject `json:"remove_records,omitempty"`
	DeleteRecords []*StatusObject `json:"delete_records,omitempty"`
}

type PreDeleteObject struct {
	ObjectUid        string `json:"object_uid,omitempty"`
	ObjectType       string `json:"object_type,omitempty"`
	FromUid          string `json:"from_uid,omitempty"`
	FromType         string `json:"from_type,omitempty"`
	DeleteResolution string `json:"delete_resolution,omitempty"`
}
type PreDeleteCommand struct {
	KeeperApiResponse
	Objects []*PreDeleteObject `json:"objects,omitempty"`
}