package sdk

import (
	"fmt"
	"github.com/golang/glog"
	"time"
)

type Vault interface {
	VaultData
	Auth
	SyncDown() chan bool
	ResolveRecordAccessPath(path *RecordAccessPath, forEdit bool, forShare bool) bool
	AddRecord(record *PasswordRecord, folderUid string) error
	PutRecord(record *PasswordRecord, skipData bool, skipExtra bool) error
	DeleteRecord(recordUid string, folderUid string, force bool) error
}

type RecordAccessPath struct {
	RecordUid string
	SharedFolderUid string
	TeamUid string
}

type vault struct {
	VaultData
	Auth
}

func NewVault(auth Auth, settings VaultStorage) Vault {
	if settings == nil {
		settings = NewInMemoryVaultStorage()
	}

	return &vault{
		Auth: auth,
		VaultData: NewVaultData(auth.AuthContext().ClientKey, settings),
	}
}

func (v *vault) syncDown(whenDone chan bool) {
	var err error
	defer (func() { whenDone <- err == nil })()

	var toRebuild *rebuildTask
	if toRebuild, err = syncDown(v); err == nil {
		v.rebuildData(toRebuild)
	} else {
		glog.V(1).Info("Sync Down error: ", err)
	}
}

func (v *vault) SyncDown() chan bool {
	f := make(chan bool)
	go v.syncDown(f)
	return f
}

func (v *vault) ResolveRecordAccessPath(path *RecordAccessPath, forEdit bool, forShare bool) (ok bool) {
	if path == nil || path.RecordUid == "" {
		return
	}

	v.VaultStorage().RecordKeys().GetLinksForSubject(path.RecordUid, func(srk StorageRecordKey) (next bool) {
		next = true
		if (forEdit && !srk.CanEdit()) || (forShare && !srk.CanShare()) {
			return
		}
		if srk.EncryptorUid() == v.VaultStorage().PersonalScopeUid() {
			ok = true
		} else {
			if sharedFolder := v.VaultStorage().SharedFolders().Get(srk.EncryptorUid()); sharedFolder != nil {
				v.VaultStorage().SharedFolderKeys().GetLinksForSubject(sharedFolder.SharedFolderUid(),
					func(ssfk StorageSharedFolderKey) bool {
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
	recordKey := GenerateAesKey()
	var encRecordKey []byte
	if encRecordKey, err = EncryptAesV1(recordKey, v.AuthContext().DataKey); err != nil {
		command := & RecordAddCommand {
			RecordUid:        GenerateUid(),
			RecordType:       "password",
			RecordKey:        Base64UrlEncode(encRecordKey),
			HowLongAgo:       0,
		}
		if folder != nil {
			command.FolderUid = folder.FolderUid
			command.FolderType = folder.FolderType
			if folder.SharedFolderUid != "" {
				if sharedFolder := v.GetSharedFolder(folder.SharedFolderUid); sharedFolder != nil {
					if encRecordKey, err = EncryptAesV1(recordKey, sharedFolder.sharedFolderKey); err == nil {
						command.FolderKey = Base64UrlEncode(encRecordKey)
					} else {
						glog.V(1).Info(err)
						err = nil
					}
				}
			}
		}
		var data []byte
		var extra []byte
		var udata []byte
		if data, extra, udata, err = record.Serialize(nil); err == nil {
			if data != nil {
				if data, err = EncryptAesV1(data, v.AuthContext().DataKey); err == nil {
					command.Data = Base64UrlEncode(data)
				} else {
					return
				}
			}
			if extra != nil {
				if extra, err = EncryptAesV1(extra, v.AuthContext().DataKey); err == nil {
					command.Data = Base64UrlEncode(data)
				} else {
					return
				}
			}
			if udata != nil {
				command.Udata = string(udata)
			}
			err = v.ExecuteAuthCommand(command, new(KeeperApiResponse), true)
		}
	}

	return
}

func (v *vault) PutRecord(record *PasswordRecord, skipData bool, skipExtra bool) (err error) {
	path := &RecordAccessPath{
		RecordUid: record.RecordUid,
	}
	if !v.ResolveRecordAccessPath(path, true, false) {
		err = NewKeeperError(fmt.Sprint("Not enough permissions to edit record: ", record.RecordUid))
		return
	}
	var storageRecord = v.VaultStorage().Records().Get(record.RecordUid)
	if storageRecord == nil {
		err = NewKeeperError(fmt.Sprint("Cannot find record: " + record.RecordUid))
		return
	}
	recordObject := &RecordObject{
		RecordUid:          path.RecordUid,
		SharedFolderUid:    path.SharedFolderUid,
		TeamUid:            path.TeamUid,
		Version:            2,
		Revision:           storageRecord.Revision(),
		ClientModifiedTime: time.Now().Unix() * 1000,
	}
	if rk := v.VaultStorage().RecordKeys().GetLink(record.RecordUid, v.VaultStorage().PersonalScopeUid()); rk != nil {
		if rk.KeyType() != 1 {
			var encKey []byte
			if encKey, err = EncryptAesV1(record.recordKey, v.AuthContext().DataKey); err == nil {
				recordObject.RecordKey = Base64UrlEncode(encKey)
			} else {
				glog.V(2).Info(err)
			}
		}
	}
	if !skipData || !skipExtra {
		var data []byte
		var extra []byte
		var udata []byte
		data, extra, udata, err = record.Serialize(storageRecord)
		if err != nil {
			return
		}

		if !skipData && data != nil {
			if data, err = EncryptAesV1(data, record.recordKey); err != nil {
				return
			}
			recordObject.Data = Base64UrlEncode(data)
		}
		if !skipExtra && extra != nil {
			if extra, err = EncryptAesV1(extra, record.recordKey); err != nil {
				return
			}
			recordObject.Extra = Base64UrlEncode(extra)
			if udata != nil {
				recordObject.Udata = string(udata)
			}
		}
	}

	var command = &RecordUpdateCommand{
		Pt:            DefaultDeviceName,
		ClientTime:    time.Now().Unix() * 1000,
		UpdateRecords: []*RecordObject{recordObject},
	}
	var rs = new(RecordUpdateResponse)
	if err = v.ExecuteAuthCommand(command, rs, true); err == nil {
		if rs.UpdateRecords != nil {
			if len(rs.UpdateRecords) == 1 {
				var rus = rs.UpdateRecords[0]
				if rus.Status != "success" {
					err = &KeeperApiError{
						resultCode: rus.Status,
					}
				}
				return
			}
		}
	}
	if err == nil {
		err = NewKeeperError(fmt.Sprint("Record Update: unexpected response"))
	}
	return
}

func (v *vault) DeleteRecord(recordUid string, folderUid string, force bool) (err error) {
	record := v.GetRecord(recordUid)
	if record == nil {
		err = NewKeeperError(fmt.Sprint("Record not found: ", recordUid))
		return
	}

	path := &RecordAccessPath{
		RecordUid: recordUid,
	}
	if !v.ResolveRecordAccessPath(path, true, false) {
		err = NewKeeperError(fmt.Sprint("Not enough permissions to delete record: ", recordUid))
		return
	}

	if folderUid == "" {
		if !force && v.Ui() != nil {
			if !v.Ui().Confirmation("Delete a record?") {
				return
			}
		}
		command := &RecordUpdateCommand{
			Pt:         DefaultDeviceName,
			ClientTime: time.Now().Unix() * 1000,
		}
		if record.Owner() {
			command.DeleteRecords = []string{record.RecordUid}
		} else {
			command.RemoveRecords = []string{record.RecordUid}
		}
		var rs = new(RecordUpdateResponse)
		if err = v.ExecuteAuthCommand(command, rs, true); err == nil {
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
						err = &KeeperApiError{
							resultCode: rds.Status,
						}
					}
					return
				}
			}
		}
	} else {

	}
	return
}
