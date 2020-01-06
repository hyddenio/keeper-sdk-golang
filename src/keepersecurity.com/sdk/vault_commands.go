package sdk

type RecordAddCommand struct {
	AuthorizedCommand
	RecordUid  string                 `json:"record_uid,omitempty"`
	RecordType string                 `json:"record_type,omitempty"`
	RecordKey  string                 `json:"record_key,omitempty"`
	HowLongAgo float64                `json:"how_long_ago,omitempty"`
	FolderType string                 `json:"folder_type,omitempty"`
	FolderUid  string                 `json:"folder_uid,omitempty"`
	FolderKey  string                 `json:"folder_key,omitempty"`
	Data       string                 `json:"data,omitempty"`
	Extra      string                 `json:"extra,omitempty"`
	Udata      map[string]interface{} `json:"udata,omitempty"`
}
func (c *RecordAddCommand) Command() string {
	return "record_add"
}

type RecordObject struct {
	RecordUid          string                 `json:"record_uid,omitempty"`
	SharedFolderUid    string                 `json:"shared_folder_uid,omitempty"`
	TeamUid            string                 `json:"team_uid,omitempty"`
	Version            int32                  `json:"version,omitempty"`
	Revision           int64                  `json:"revision,omitempty"`
	RecordKey          string                 `json:"record_key,omitempty"`
	ClientModifiedTime float64                `json:"client_modified_time,omitempty"`
	Data               string                 `json:"data,omitempty"`
	Extra              string                 `json:"extra,omitempty"`
	Udata              map[string]interface{} `json:"udata,omitempty"`
	NonSharedData      string                 `json:"non_shared_data,omitempty"`
}

type RecordUpdateCommand struct {
	AuthorizedCommand
	DeviceId      string          `json:"device_id,omitempty"`
	Pt            string          `json:"pt,omitempty"`
	ClientTime    float64         `json:"client_time,omitempty"`
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

type RequestUploadCommand struct {
	AuthorizedCommand
	FileCount      int `json:"file_count,omitempty"`
	ThumbnailCount int `json:"thumbnail_count,omitempty"`
}
func (c *RequestUploadCommand) Command() string {
	return "request_upload"
}

type UploadObject struct {
	MaxSize           float64                `json:"max_size"`
	Url               string                 `json:"url"`
	SuccessStatusCode int                    `json:"success_status_code"`
	FileId            string                 `json:"file_id"`
	FileParameter     string                 `json:"file_parameter"`
	Parameters        map[string]interface{} `json:"parameters"`
}
type RequestUploadResponse struct {
	KeeperApiResponse
	FileUploads      []*UploadObject `json:"file_uploads"`
	ThumbnailUploads []*UploadObject `json:"thumbnail_uploads"`
}

type RequestDownloadCommand struct {
	AuthorizedCommand
	RecordUid       string   `json:"record_uid,omitempty"`
	SharedFolderUid string   `json:"shared_folder_uid,omitempty"`
	TeamUid         string   `json:"team_uid,omitempty"`
	FileIds         []string `json:"file_ids,omitempty"`
}
func (c *RequestDownloadCommand) Command() string {
	return "request_download"
}

type DownloadObject struct {
	Url string `json:"url"`
}
type RequestDownloadResponse struct {
	KeeperApiResponse
	Downloads []*DownloadObject `json:"downloads"`
}