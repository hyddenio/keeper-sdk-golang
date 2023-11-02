package vault

import (
  "bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/golang/glog"
	"keepersecurity.com/sdk/auth"
)

type Vault interface {
  VaultData
  Auth() auth.IKeeperConnection
	SyncDown() error
	SyncDownAsync() chan error
	ResolveRecordAccessPath(path *RecordAccessPath, forEdit bool, forShare bool) bool
	AddRecord(record *PasswordRecord, folderUid string) error
	PutRecord(record *PasswordRecord, skipData bool, skipExtra bool) error
	DeleteRecord(recordUid string, folderUid string) error
	UploadAttachment(fileBody io.Reader) (*AttachmentFile, error)
	DownloadAttachment(record *PasswordRecord, attachmentId string, fileBody io.Writer) error
}

type RecordAccessPath struct {
	RecordUid string
	SharedFolderUid string
	TeamUid string
}

type vault struct {
  VaultData
  auth auth.IKeeperConnection
}

func NewVault(auth auth.IKeeperConnection, storage IVaultStorage) Vault {
	if storage == nil {
		storage = NewInMemoryVaultStorage()
	}

	return &vault{
		auth:      auth,
		VaultData: NewVaultData(auth.AuthContext().ClientKey(), storage),
	}
}
func (v *vault) Auth() auth.IKeeperConnection {
	return v.auth
}
func (v *vault) SyncDown() (err error) {
	var toRebuild *rebuildTask
	if toRebuild, err = syncDown(v); err == nil {
		v.rebuildData(toRebuild)
	} else {
		glog.V(1).Info("Sync Down error: ", err)
	}
	return
}

func (v *vault) SyncDownAsync() chan error {
	f := make(chan error)
	go func() {
		f <- v.SyncDown()
		close(f)
	}()
	return f
}

func (v *vault) ResolveRecordAccessPath(path *RecordAccessPath, forEdit bool, forShare bool) (ok bool) {
	if path == nil || path.RecordUid == "" {
		return
	}

	v.VaultStorage().RecordKeys().GetLinksForSubject(path.RecordUid, func(srk IStorageRecordKey) (next bool) {
		next = true
		if (forEdit && !srk.CanEdit()) || (forShare && !srk.CanShare()) {
			return
		}
		if srk.EncryptorUid() == v.VaultStorage().PersonalScopeUid() {
			ok = true
		} else {
			if sharedFolder := v.VaultStorage().SharedFolders().Get(srk.EncryptorUid()); sharedFolder != nil {
				v.VaultStorage().SharedFolderKeys().GetLinksForSubject(sharedFolder.SharedFolderUid(),
					func(ssfk IStorageSharedFolderKey) bool {
						if ssfk.EncryptorUid() == "" {
							path.SharedFolderUid = sharedFolder.SharedFolderUid()
							ok = true
						} else {
							if team := v.VaultStorage().Teams().Get(ssfk.EncryptorUid()); team != nil {
								if (!forEdit || srk.CanEdit()) && (!forShare || srk.CanShare()) {
									path.SharedFolderUid = sharedFolder.SharedFolderUid()
									path.TeamUid = team.TeamUid()
									ok = true
								}
							}
						}
						return !ok
					})
			}
		}
		return !ok
	})

	return
}

func (v *vault) AddRecord(record *PasswordRecord, folderUid string) (err error) {
	var folder *Folder = nil
	if folderUid != "" {
		folder = v.GetFolder(folderUid)
	}
	recordKey := auth.GenerateAesKey()
	var encRecordKey []byte
	if encRecordKey, err = auth.EncryptAesV1(recordKey, v.Auth().AuthContext().DataKey()); err != nil {
		command := &RecordAddCommand{
			RecordUid:  auth.GenerateUid(),
			RecordType: "password",
			RecordKey:  auth.Base64UrlEncode(encRecordKey),
			HowLongAgo: 0,
		}
		if folder != nil {
			command.FolderUid = folder.FolderUid
			command.FolderType = folder.FolderType
			if folder.SharedFolderUid != "" {
				if sharedFolder := v.GetSharedFolder(folder.SharedFolderUid); sharedFolder != nil {
					if encRecordKey, err = auth.EncryptAesV1(recordKey, sharedFolder.sharedFolderKey); err == nil {
						command.FolderKey = auth.Base64UrlEncode(encRecordKey)
					} else {
						glog.V(1).Info(err)
						err = nil
					}
				}
			}
		}
		var data []byte
		var extra []byte
		var udata map[string]interface{}
		if data, extra, udata, err = record.Serialize(nil); err == nil {
			if data != nil {
				if data, err = auth.EncryptAesV1(data, recordKey); err == nil {
					command.Data = auth.Base64UrlEncode(data)
				} else {
					return
				}
			}
			if extra != nil {
				if extra, err = auth.EncryptAesV1(extra, recordKey); err == nil {
					command.Data = auth.Base64UrlEncode(data)
				} else {
					return
				}
			}
			if udata != nil {
				command.Udata = udata
			}
			err = v.Auth().ExecuteAuthCommand(command, new(auth.KeeperApiResponse), true)
		}
	}

	return
}

func (v *vault) PutRecord(record *PasswordRecord, skipData bool, skipExtra bool) (err error) {
	path := &RecordAccessPath{
		RecordUid: record.RecordUid,
	}
	if !v.ResolveRecordAccessPath(path, true, false) {
		err = auth.NewKeeperError(fmt.Sprint("Not enough permissions to edit record: ", record.RecordUid))
		return
	}
	var storageRecord = v.VaultStorage().Records().Get(record.RecordUid)
	if storageRecord == nil {
		err = auth.NewKeeperError(fmt.Sprint("Cannot find record: " + record.RecordUid))
		return
	}
	recordObject := &RecordObject{
		RecordUid:          path.RecordUid,
		SharedFolderUid:    path.SharedFolderUid,
		TeamUid:            path.TeamUid,
		Version:            2,
		Revision:           storageRecord.Revision(),
		ClientModifiedTime: float64(time.Now().Unix() * 1000),
	}
	if rk := v.VaultStorage().RecordKeys().GetLink(record.RecordUid, v.VaultStorage().PersonalScopeUid()); rk != nil {
		if rk.KeyType() != 1 {
			var encKey []byte
			if encKey, err = auth.EncryptAesV1(record.recordKey, v.Auth().AuthContext().DataKey()); err == nil {
				recordObject.RecordKey = auth.Base64UrlEncode(encKey)
			} else {
				glog.V(2).Info(err)
			}
		}
	}
	if !skipData || !skipExtra {
		var data []byte
		var extra []byte
		var udata map[string]interface{}
		data, extra, udata, err = record.Serialize(storageRecord)
		if err != nil {
			return
		}

		if !skipData && data != nil {
			if data, err = auth.EncryptAesV1(data, record.recordKey); err != nil {
				return
			}
			recordObject.Data = auth.Base64UrlEncode(data)
		}
		if !skipExtra && extra != nil {
			if extra, err = auth.EncryptAesV1(extra, record.recordKey); err != nil {
				return
			}
			recordObject.Extra = auth.Base64UrlEncode(extra)
			if udata != nil {
				recordObject.Udata = udata
			}
		}
	}

	var command = &RecordUpdateCommand{
		Pt:            auth.DefaultDeviceName,
		DeviceId:      auth.DefaultDeviceName,
		ClientTime:    float64(time.Now().Unix() * 1000),
		UpdateRecords: []*RecordObject{recordObject},
	}
	var rs = new(RecordUpdateResponse)
	if err = v.Auth().ExecuteAuthCommand(command, rs, true); err == nil {
		if rs.UpdateRecords != nil {
			if len(rs.UpdateRecords) == 1 {
				var rus = rs.UpdateRecords[0]
				if rus.Status != "success" {
					err = auth.NewKeeperApiError(rus.Status, "Put record error")
				}
				return
			}
		}
	}
	if err == nil {
		err = auth.NewKeeperError(fmt.Sprint("Record Update: unexpected response"))
	}
	return
}

func (v *vault) DeleteRecord(recordUid string, folderUid string) (err error) {
	record := v.GetRecord(recordUid)
	if record == nil {
		err = auth.NewKeeperError(fmt.Sprint("Record not found: ", recordUid))
		return
	}

	path := &RecordAccessPath{
		RecordUid: recordUid,
	}
	if !v.ResolveRecordAccessPath(path, true, false) {
		err = auth.NewKeeperError(fmt.Sprint("Not enough permissions to delete record: ", recordUid))
		return
	}

	if folderUid == "" {
		command := &RecordUpdateCommand{
			Pt:         auth.DefaultDeviceName,
			ClientTime: float64(time.Now().Unix() * 1000),
		}
		if record.Owner() {
			command.DeleteRecords = []string{record.RecordUid}
		} else {
			command.RemoveRecords = []string{record.RecordUid}
		}
		var rs = new(RecordUpdateResponse)
		if err = v.Auth().ExecuteAuthCommand(command, rs, true); err == nil {
			var statuses []*StatusObject = nil
			if record.Owner() {
				statuses = rs.DeleteRecords
			} else {
				statuses = rs.RemoveRecords
			}
			if statuses != nil {
				if len(statuses) == 1 {
					var rds = statuses[0]
					if rds.Status != "success" {
						err = auth.NewKeeperApiError(rds.Status, "Record delete error")
					}
					return
				}
			}
		}
	} else {
		//TODO
	}
	return
}

type uploadMultipartReader struct {
	err             error
	fileParameter   string
	fileName        string
	fileReader      auth.StreamCryptor
	fileWriter      io.Writer
	multipartWriter *multipart.Writer
	buffer          *bytes.Buffer
}

func (mp *uploadMultipartReader) Read(result []byte) (read int, err error) {
	read = 0
	err = nil
	var fits int
	for fits = len(result) - read; fits > 0; fits = len(result) - read {
		avail := mp.buffer.Len()
		if avail > 0 {
			toSend := fits
			if avail < toSend {
				toSend = avail
			}
			var n int
			n, err = mp.buffer.Read(result[read:])
			read += n
		} else {
			if mp.fileWriter == nil {
				mp.fileWriter, mp.err = mp.multipartWriter.CreateFormFile(mp.fileParameter, mp.fileName)
			}
			if mp.err == nil {
				var toRead = int64(mp.buffer.Cap() - mp.buffer.Len())
				var written int64
				written, mp.err = io.CopyN(mp.fileWriter, mp.fileReader, toRead)
				if mp.err != nil {
					_ = mp.multipartWriter.Close()
				}
				if written == 0 {
					break
				}
			} else {
				break
			}
		}
	}

	if mp.buffer.Len() == 0 && mp.err != nil {
		err = mp.err
	}

	return
}

func (v *vault) UploadAttachment(fileBody io.Reader) (result *AttachmentFile, err error) {
	rq := &RequestUploadCommand{
		FileCount:      1,
		ThumbnailCount: 0,
	}
	rs := new(RequestUploadResponse)
	if err = v.Auth().ExecuteAuthCommand(rq, rs, true); err != nil {
		return
	}

	upload := rs.FileUploads[0]
	var af = &AttachmentFile{
		Id:   upload.FileId,
		Size: 0,
		Key:  auth.GenerateAesKey(),
	}

	uploader := new(uploadMultipartReader)
	uploader.err = nil
	encryptor := auth.NewAesStreamEncryptor(fileBody, af.Key)
	uploader.fileReader = encryptor
	uploader.buffer = bytes.NewBuffer(make([]byte, 0, 10240))
	uploader.multipartWriter = multipart.NewWriter(uploader.buffer)
	if len(upload.Parameters) > 0 {
		for k, v := range upload.Parameters {
			if s, ok := v.(string); ok {
				_ = uploader.multipartWriter.WriteField(k, s)
			}
		}
	}
	uploader.fileParameter = upload.FileParameter
	uploader.fileName = upload.FileId

	var httpRq *http.Request
	if httpRq, err = http.NewRequest("POST", upload.Url, uploader); err == nil {
		httpRq.Header.Set("Content-Type", uploader.multipartWriter.FormDataContentType())
		client := http.DefaultClient
		var httpRs *http.Response
		if httpRs, err = client.Do(httpRq); err == nil {
			if httpRs.StatusCode == upload.SuccessStatusCode {
				af.Size = int32(encryptor.GetTotal())
			} else {
				err = errors.New(fmt.Sprintf("upload HTTP status code: %d, expected: %d", httpRs.StatusCode, upload.SuccessStatusCode))
			}
			_ = httpRs.Body.Close()
		}
	}

	if err == nil {
		result = af
	}
	return
}

func (v *vault) DownloadAttachment(record *PasswordRecord, attachment string, fileBody io.Writer) (err error) {
	var attachmentId string
	var key []byte
	for _, atta := range record.Attachments {
		if atta.Id == attachment {
			attachmentId = atta.Id
			key = atta.Key
			break
		}
		for _, th := range atta.Thumbnails {
			if th.Id == attachment {
				attachmentId = th.Id
				key = atta.Key
				break
			}
		}
		if attachmentId != "" {
			break
		}
	}
	if attachmentId == "" {
		for _, atta := range record.Attachments {
			if atta.Name == attachment || atta.Title == attachment {
				attachmentId = atta.Id
				key = atta.Key
				break
			}
		}
	}
	if attachmentId == "" {
		err = errors.New("file attachment not found")
		return
	}

	path := &RecordAccessPath{
		RecordUid: record.RecordUid,
	}
	if !v.ResolveRecordAccessPath(path, false, false) {
		err = auth.NewKeeperError(fmt.Sprint("not enough permissions to read record: ", record.RecordUid))
		return
	}

	rq := &RequestDownloadCommand{
		RecordUid:       path.RecordUid,
		SharedFolderUid: path.SharedFolderUid,
		TeamUid:         path.TeamUid,
		FileIds:         []string{attachmentId},
	}
	rs := new(RequestDownloadResponse)
	if err = v.Auth().ExecuteAuthCommand(rq, rs, true); err != nil {
		return
	}
	if len(rs.Downloads) != 1 {
		err = errors.New("invalid response")
		return
	}
	download := rs.Downloads[0]
	var httpRq *http.Request
	if httpRq, err = http.NewRequest("GET", download.Url, nil); err == nil {
		client := http.DefaultClient
		var httpRs *http.Response
		if httpRs, err = client.Do(httpRq); err == nil {
			if httpRs.StatusCode == 200 {
				decryptor := auth.NewAesStreamDecryptor(httpRs.Body, key)
				_, err = io.Copy(fileBody, decryptor)
			} else {
				err = errors.New(fmt.Sprint("download attachment http error: ", httpRs.StatusCode))
			}
			_ = httpRs.Body.Close()
		}
	}
	return
}
