package vault

import (
	auth "keepersecurity.com/sdk/auth"
)

type RecordAddCommand struct {
	auth.AuthorizedCommand
	RecordUid  string                 `json:"record_uid"`
	RecordType string                 `json:"record_type"`
	RecordKey  string                 `json:"record_key"`
	HowLongAgo float64                `json:"how_long_ago"`
	FolderType string                 `json:"folder_type"`
	FolderUid  string                 `json:"folder_uid"`
	FolderKey  string                 `json:"folder_key"`
	Data       string                 `json:"data"`
	Extra      string                 `json:"extra"`
	Udata      map[string]interface{} `json:"udata"`
}

func (c *RecordAddCommand) Command() string {
	return "record_add"
}

type RecordObject struct {
	RecordUid          string                 `json:"record_uid"`
	SharedFolderUid    string                 `json:"shared_folder_uid"`
	TeamUid            string                 `json:"team_uid"`
	Version            int32                  `json:"version"`
	Revision           int64                  `json:"revision"`
	RecordKey          string                 `json:"record_key"`
	ClientModifiedTime float64                `json:"client_modified_time"`
	Data               string                 `json:"data"`
	Extra              string                 `json:"extra"`
	Udata              map[string]interface{} `json:"udata"`
	NonSharedData      string                 `json:"non_shared_data"`
}

type RecordUpdateCommand struct {
	auth.AuthorizedCommand
	DeviceId      string          `json:"device_id"`
	Pt            string          `json:"pt"`
	ClientTime    float64         `json:"client_time"`
	AddRecords    []*RecordObject `json:"add_records"`
	UpdateRecords []*RecordObject `json:"update_records"`
	RemoveRecords []string        `json:"remove_records"`
	DeleteRecords []string        `json:"delete_records"`
}

func (c *RecordUpdateCommand) Command() string {
	return "record_update"
}

type StatusObject struct {
	RecordUid string `json:"record_uid"`
	Status    string `json:"status"`
}

type RecordUpdateResponse struct {
	auth.KeeperApiResponse
	AddRecords    []*StatusObject `json:"add_records"`
	UpdateRecords []*StatusObject `json:"update_records"`
	RemoveRecords []*StatusObject `json:"remove_records"`
	DeleteRecords []*StatusObject `json:"delete_records"`
}

type PreDeleteObject struct {
	ObjectUid        string `json:"object_uid"`
	ObjectType       string `json:"object_type"`
	FromUid          string `json:"from_uid"`
	FromType         string `json:"from_type"`
	DeleteResolution string `json:"delete_resolution"`
}
type PreDeleteCommand struct {
	auth.KeeperApiResponse
	Objects []*PreDeleteObject `json:"objects"`
}

type RequestUploadCommand struct {
	auth.AuthorizedCommand
	FileCount      int `json:"file_count"`
	ThumbnailCount int `json:"thumbnail_count"`
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
	auth.KeeperApiResponse
	FileUploads      []*UploadObject `json:"file_uploads"`
	ThumbnailUploads []*UploadObject `json:"thumbnail_uploads"`
}

type RequestDownloadCommand struct {
	auth.AuthorizedCommand
	RecordUid       string   `json:"record_uid"`
	SharedFolderUid string   `json:"shared_folder_uid"`
	TeamUid         string   `json:"team_uid"`
	FileIds         []string `json:"file_ids"`
}

func (c *RequestDownloadCommand) Command() string {
	return "request_download"
}

type DownloadObject struct {
	Url string `json:"url"`
}
type RequestDownloadResponse struct {
	auth.KeeperApiResponse
	Downloads []*DownloadObject `json:"downloads"`
}
