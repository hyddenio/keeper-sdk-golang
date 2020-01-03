package sdk

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"time"
)

func syncDown(vault Vault) (result *rebuildTask, err error) {
	var storage = vault.VaultStorage()
	var auth Auth = vault
	rq := &SyncDownCommand{
		Revision:   storage.Revision(),
		Include:    []string{"sfheaders", "sfrecords", "sfusers", "teams", "folders"},
		DeviceId:   DefaultDeviceName,
		DeviceName: DefaultDeviceName,
		ClientTime: time.Now().Unix() * 1000,
	}
	rs := new(SyncDownResponse)
	if err = auth.ExecuteAuthCommand(rq, rs, true); err != nil {
		return
	}

	var fullSync = rs.FullSync
	if fullSync {
		storage.Clear()
	}
	result = new(rebuildTask)
	result.isFullSync = fullSync

	storage.SetRevision(rs.Revision)
	var recordUid string
	var sharedFolderUid string
	var teamUid string
	var folderUid string
	var username string

	if rs.RemovedRecords != nil {
		for _, recordUid = range rs.RemovedRecords {
			result.addRecord(recordUid)

			storage.RecordKeys().Delete(recordUid, storage.PersonalScopeUid())
			// remove record from all user folders
			storage.FolderRecords().GetLinksForObject(recordUid, func(sfr StorageFolderRecord) bool {
				folderUid = sfr.FolderUid()
				if folderUid == "" || folderUid == storage.PersonalScopeUid() {
					storage.FolderRecords().DeleteLink(sfr)
				} else {
					if folder := storage.Folders().Get(folderUid); folder != nil {
						if folder.FolderType() == "user_folder" {
							storage.FolderRecords().DeleteLink(sfr)
						}
					}
				}
				return true
			})
		}
	}

	if rs.RemovedTeams != nil {
		for _, teamUid = range rs.RemovedTeams {
			storage.SharedFolderKeys().GetLinksForObject(teamUid, func(ssfk StorageSharedFolderKey) bool {
				sharedFolderUid = ssfk.SharedFolderUid()
				storage.RecordKeys().GetLinksForObject(sharedFolderUid, func(srk StorageRecordKey) bool {
					result.addRecord(srk.RecordUid())
					return true
				})
				result.addSharedFolder(sharedFolderUid)
				return true
			})
			storage.SharedFolderKeys().DeleteObject(teamUid)
			storage.TeamKeys().DeleteSubject(teamUid)
			storage.Teams().Delete(teamUid)
		}
	}

	if rs.RemovedSharedFolders != nil {
		for _, sharedFolderUid = range rs.RemovedSharedFolders {
			result.addSharedFolder(sharedFolderUid)
			storage.RecordKeys().GetLinksForObject(sharedFolderUid, func(srk StorageRecordKey) bool {
				result.addRecord(srk.RecordUid())
				return true
			})
			storage.SharedFolderKeys().Delete(sharedFolderUid, storage.PersonalScopeUid())
		}
	}

	if rs.UserFoldersRemoved != nil {
		for _, ufr := range rs.UserFoldersRemoved {
			folderUid = ufr.FolderUid_
			storage.FolderRecords().DeleteSubject(folderUid)
			storage.Folders().Delete(folderUid)
		}
	}

	if rs.SharedFolderFolderRemoved != nil {
		for _, sffr := range rs.SharedFolderFolderRemoved {
			if sffr.FolderUid_ != "" {
				folderUid = sffr.FolderUid_
			} else {
				folderUid = sffr.SharedFolderUid_
			}
			storage.FolderRecords().DeleteSubject(folderUid)
			storage.Folders().Delete(folderUid)
		}
	}

	if rs.UserFolderSharedFoldersRemoved != nil {
		for _, ufsfr := range rs.UserFolderSharedFoldersRemoved {
			folderUid = ufsfr.SharedFolderUid_
			storage.FolderRecords().DeleteSubject(folderUid)
			storage.Folders().Delete(folderUid)
		}
	}

	if rs.UserFoldersRemovedRecords != nil {
		for _, ufrr := range rs.UserFoldersRemovedRecords {
			if ufrr.FolderUid_ != "" {
				folderUid = ufrr.FolderUid_
			} else {
				folderUid = storage.PersonalScopeUid()
			}
			recordUid = ufrr.RecordUid_
			storage.FolderRecords().Delete(folderUid, recordUid)
		}
	}

	if rs.SharedFolderFolderRecordsRemoved != nil {
		for _, sffrr := range rs.SharedFolderFolderRecordsRemoved {
			if sffrr.FolderUid_ != "" {
				folderUid = sffrr.FolderUid_
			} else {
				folderUid = sffrr.SharedFolderUid_
			}
			recordUid = sffrr.RecordUid_
			storage.FolderRecords().Delete(folderUid, recordUid)
		}
	}

	if rs.SharedFolders != nil {
		for _, sf := range rs.SharedFolders {
			sharedFolderUid = sf.SharedFolderUid_
			if sf.FullSync {
				storage.RecordKeys().DeleteObject(sharedFolderUid)
				storage.SharedFolderKeys().DeleteSubject(sharedFolderUid)
				storage.SharedFolderPermissions().DeleteSubject(sharedFolderUid)
			} else {
				if sf.RecordsRemoved != nil {
					for _, recordUid := range sf.RecordsRemoved {
						result.addRecord(recordUid)
						storage.RecordKeys().Delete(recordUid, sharedFolderUid)
					}
				}
				if sf.TeamsRemoved != nil {
					for _, teamUid := range sf.TeamsRemoved {
						storage.SharedFolderKeys().Delete(sharedFolderUid, teamUid)
						storage.SharedFolderPermissions().Delete(sharedFolderUid, teamUid)
					}
				}
				if sf.UsersRemoved != nil {
					for _, username = range sf.UsersRemoved {
						storage.SharedFolderPermissions().Delete(sharedFolderUid, username)
					}
				}
			}
		}
	}

	var data []byte
	if rs.NonSharedData != nil {
		for _, nsd := range rs.NonSharedData {
			recordUid = nsd.RecordUid()
			if data, err = DecryptAesV1(Base64UrlDecode(nsd.Data()), auth.AuthContext().DataKey); err == nil {
				if data, err = EncryptAesV1(data, auth.AuthContext().ClientKey); err == nil {
					storage.NonSharedData().Put(nsd)
				}
			}
			if err != nil {
				glog.V(1).Info("Error decrypting Non Shared Data", err)
			}
		}
	}

	if rs.Records != nil {
		for _, r := range rs.Records {
			recordUid = r.RecordUid()
			result.addRecord(recordUid)
			r.AdjustUdata()
			storage.Records().Put(r)
		}
	}

	if rs.RecordMetaData != nil {
		for _, rmd := range rs.RecordMetaData {
			recordUid = rmd.RecordUid()
			result.addRecord(recordUid)

			if record := storage.Records().Get(recordUid); record != nil {
				if record.Owner() != rmd.Owner {
					record.SetOwner(rmd.Owner)
					storage.Records().Put(record)
				}
			}
			var key []byte
			err = nil
			switch rmd.RecordKeyType_ {
			case 0:
				key = auth.AuthContext().DataKey
			case 1:
				key, err = DecryptAesV1(Base64UrlDecode(rmd.RecordKey_), auth.AuthContext().DataKey)
			case 2:
				key, err = DecryptRsa(Base64UrlDecode(rmd.RecordKey_), auth.AuthContext().PrivateKey)
			default:
				err = NewKeeperError(fmt.Sprintf("Unsuppoted key type: %d", rmd.RecordKeyType_))
			}
			if key != nil {
				if key, err = EncryptAesV1(key, auth.AuthContext().ClientKey); err == nil {
					rmd.RecordKey_ = Base64UrlEncode(key)
					rmd.encryptorUid = storage.PersonalScopeUid()
					storage.RecordKeys().Put(rmd)
				}
			}
			if err != nil {
				glog.V(1).Info("Decrypt record metadata UID: ", recordUid, "Error: ", err)
			}
		}
	}

	if rs.Teams != nil {
		for _, team := range rs.Teams {
			teamUid = team.TeamUid_
			if team.RemovedSharedFolders != nil {
				for _, sharedFolderUid = range team.RemovedSharedFolders {
					result.addSharedFolder(sharedFolderUid)
					storage.SharedFolderKeys().Delete(sharedFolderUid, teamUid)
				}
			}
			var key []byte
			err = nil
			switch team.TeamKeyType_ {
			case 1:
				key, err = DecryptAesV1(Base64UrlDecode(team.TeamKey_), auth.AuthContext().DataKey)
			case 2:
				key, err = DecryptRsa(Base64UrlDecode(team.TeamKey_), auth.AuthContext().PrivateKey)
			default:
				err = NewKeeperError(fmt.Sprintf("Unsuppoted key type: %d", team.TeamKeyType_))
			}
			if key != nil {
				var teamKey = key
				if key, err = EncryptAesV1(key, auth.AuthContext().ClientKey); err == nil {
					team.TeamKey_ = Base64UrlEncode(key)
					team.encryptorUid = storage.PersonalScopeUid()
					storage.TeamKeys().Put(team)
					storage.Teams().Put(team)
					if team.SharedFolderKeys != nil {
						var teamPrivateKey crypto.PrivateKey
						for _, sfk := range team.SharedFolderKeys {
							var sharedFolderKey []byte
							switch sfk.KeyType_ {
							case 1:
								sharedFolderKey = Base64UrlDecode(sfk.SharedFolderKey_)
							case 2:
								if teamPrivateKey == nil {
									if key, err = DecryptAesV1(Base64UrlDecode(team.TeamPrivateKey_), teamKey); err == nil {
										teamPrivateKey, err = LoadPrivateKey(key)
									}
								}
								if teamPrivateKey != nil {
									if key, err = DecryptRsa(Base64UrlDecode(sfk.SharedFolderKey_), teamPrivateKey); err == nil {
										sharedFolderKey, err = EncryptAesV1(key, teamKey)
									}
								}
							}
							if sharedFolderKey != nil {
								sfk.encryptorUid = teamUid
								sfk.SharedFolderKey_ = Base64UrlEncode(sharedFolderKey)
								sfk.KeyType_ = TeamKey
								storage.SharedFolderKeys().Put(sfk)
							}
						}
					}
				}
			}
		}
	}

	if rs.SharedFolders != nil {
		for _, sf := range rs.SharedFolders {
			sharedFolderUid = sf.SharedFolderUid_
			result.addSharedFolder(sharedFolderUid)
			if sf.SharedFolderKey != nil {
				var key []byte = nil
				err = nil
				switch *sf.KeyType {
				case 1:
					key, err = DecryptAesV1(Base64UrlDecode(*sf.SharedFolderKey), auth.AuthContext().DataKey)
				case 2:
					key, err = DecryptRsa(Base64UrlDecode(*sf.SharedFolderKey), auth.AuthContext().PrivateKey)
				default:
					err = NewKeeperError(fmt.Sprintf("Unsupported key type: %d", *sf.KeyType))
				}
				if key != nil {
					if key, err = EncryptAesV1(key, auth.AuthContext().ClientKey); err == nil {
						sdsfk := &SyncDownSharedFolderKey{
							SharedFolderUid_: sharedFolderUid,
							SharedFolderKey_: Base64UrlEncode(key),
							KeyType_:         UserClientKey,
							encryptorUid:     storage.PersonalScopeUid(),
						}
						storage.SharedFolderKeys().Put(sdsfk)
					}
				}
			}
			if sf.Records != nil {
				for _, sfr := range sf.Records {
					recordUid = sfr.RecordUid
					result.addRecord(recordUid)
					rmd := &SyncDownRecordMetaData{
						RecordUid_:     recordUid,
						RecordKey_:     sfr.RecordKey,
						RecordKeyType_: SharedFolderKey,
						CanShare_:      sfr.CanEdit,
						CanEdit_:       sfr.CanShare,
						encryptorUid:   sharedFolderUid,
					}
					storage.RecordKeys().Put(rmd)
				}
			}
			if sf.Teams != nil {
				for _, sft := range sf.Teams {
					sft.sharedFolderUid = sharedFolderUid
					storage.SharedFolderPermissions().Put(sft)
				}
			}
			if sf.Users != nil {
				for _, sfu := range sf.Users {
					sfu.sharedFolderUid = sharedFolderUid
					storage.SharedFolderPermissions().Put(sfu)
				}
			}
			storage.SharedFolders().Put(sf)
		}
	}

	if rs.UserFolders != nil {
		for _, uf := range rs.UserFolders {
			folderUid = uf.FolderUid_
			var key []byte
			switch uf.KeyType_ {
			case 1:
				key, err = DecryptAesV1(Base64UrlDecode(uf.UserFolderKey_), auth.AuthContext().DataKey)
			case 2:
				key, err = DecryptRsa(Base64UrlDecode(uf.UserFolderKey_), auth.AuthContext().PrivateKey)
			}
			if key != nil {
				if key, err = EncryptAesV1(key, auth.AuthContext().ClientKey); err == nil {
					uf.UserFolderKey_ = Base64UrlEncode(key)
					storage.Folders().Put(uf)
				}
			}
		}
	}

	if rs.SharedFolderFolders != nil {
		for _, sff := range rs.SharedFolderFolders {
			storage.Folders().Put(sff)
		}
	}

	if rs.UserFolderSharedFolders != nil {
		for _, ufsf := range rs.UserFolderSharedFolders {
			storage.Folders().Put(ufsf)
		}
	}

	if rs.UserFolderRecords != nil {
		for _, ufr := range rs.UserFolderRecords {
			storage.FolderRecords().Put(ufr)
		}
	}

	if rs.SharedFolderFolderRecords != nil {
		for _, sffr := range rs.SharedFolderFolderRecords {
			storage.FolderRecords().Put(sffr)
		}
	}
	return
}

// shared folder records
func (sffr *SyncDownSharedFolderFolderRecordNode) FolderUid() string {
	if sffr.FolderUid_ != "" {
		return sffr.FolderUid_
	}
	return sffr.SharedFolderUid_
}
func (sffr *SyncDownSharedFolderFolderRecordNode) RecordUid() string {
	return sffr.RecordUid_
}

func (sffr *SyncDownSharedFolderFolderRecordNode) SubjectUid() string {
	return sffr.FolderUid()
}
func (sffr *SyncDownSharedFolderFolderRecordNode) ObjectUid() string {
	return sffr.RecordUid()
}


// user folder records
func (fr *SyncDownFolderRecordNode) FolderUid() string {
	return fr.FolderUid_
}
func (fr *SyncDownFolderRecordNode) RecordUid() string {
	return fr.RecordUid_
}
func (fr *SyncDownFolderRecordNode) SubjectUid() string {
	return fr.FolderUid()
}
func (fr *SyncDownFolderRecordNode) ObjectUid() string {
	return fr.RecordUid()
}

//user folder shared folder
func (ufsf *SyncDownUserFolderSharedFolder) FolderUid() string {
	return ufsf.SharedFolderUid_
}
func (ufsf *SyncDownUserFolderSharedFolder) ParentUid() string {
	return ufsf.FolderUid_
}
func (ufsf *SyncDownUserFolderSharedFolder) FolderType() string {
	return "shared_folder"
}
func (ufsf *SyncDownUserFolderSharedFolder) SharedFolderUid() string {
	return ufsf.SharedFolderUid_
}
func (ufsf *SyncDownUserFolderSharedFolder) FolderKey() string {
	return ""
}
func (ufsf *SyncDownUserFolderSharedFolder) Data() string {
	return ""
}
func (ufsf *SyncDownUserFolderSharedFolder) Uid() string {
	return ufsf.FolderUid()
}


// shared folder folder
func (sff *SyncDownSharedFolderFolder) FolderUid() string {
	return sff.FolderUid_
}
func (sff *SyncDownSharedFolderFolder) ParentUid() string {
	return sff.ParentUid_
}
func (sff *SyncDownSharedFolderFolder) SharedFolderUid() string {
	return sff.SharedFolderUid_
}
func (sff *SyncDownSharedFolderFolder) FolderType() string {
	return sff.FolderType_
}
func (sff *SyncDownSharedFolderFolder) FolderKey() string {
	return sff.SharedFolderFolderKey_
}
func (sff *SyncDownSharedFolderFolder) Data() string {
	return sff.Data_
}
func (sff *SyncDownSharedFolderFolder) Uid() string {
	return sff.FolderUid()
}

// user folders
func (uf *SyncDownUserFolder) FolderUid() string {
	return uf.FolderUid_
}
func (uf *SyncDownUserFolder) ParentUid() string {
	return uf.ParentUid_
}
func (uf *SyncDownUserFolder) SharedFolderUid() string {
	return ""
}
func (uf *SyncDownUserFolder) FolderType() string {
	return uf.FolderType_
}
func (uf *SyncDownUserFolder) FolderKey() string {
	return uf.UserFolderKey_
}
func (uf *SyncDownUserFolder) Data() string {
	return uf.Data_
}
func (uf *SyncDownUserFolder) Uid() string {
	return uf.FolderUid()
}

//shared folder user permissions
func (sfu *SyncDownSharedFolderUser) SharedFolderUid() string {
	return sfu.sharedFolderUid
}
func (sfu *SyncDownSharedFolderUser) UserId() string {
	return sfu.Username
}
func (sfu *SyncDownSharedFolderUser) UserType() int {
	return 1
}
func (sfu *SyncDownSharedFolderUser) ManageRecords() bool {
	return sfu.ManageRecords_
}
func (sfu *SyncDownSharedFolderUser) ManageUsers() bool {
	return sfu.ManageUsers_
}
func (sfu *SyncDownSharedFolderUser) SubjectUid() string {
	return sfu.SharedFolderUid()
}
func (sfu *SyncDownSharedFolderUser) ObjectUid() string {
	return sfu.UserId()
}

// shared folder team permissions
func (sft *SyncDownSharedFolderTeam) SharedFolderUid() string {
	return sft.sharedFolderUid
}
func (sft *SyncDownSharedFolderTeam) UserId() string {
	return sft.TeamUid
}
func (sft *SyncDownSharedFolderTeam) UserType() int {
	return 2
}
func (sft *SyncDownSharedFolderTeam) ManageRecords() bool {
	return sft.ManageRecords_
}
func (sft *SyncDownSharedFolderTeam) ManageUsers() bool {
	return sft.ManageUsers_
}
func (sft *SyncDownSharedFolderTeam) SubjectUid() string {
	return sft.SharedFolderUid()
}
func (sft *SyncDownSharedFolderTeam) ObjectUid() string {
	return sft.UserId()
}

// team's shared folder keys
func (sfk *SyncDownSharedFolderKey) SharedFolderUid() string {
	return sfk.SharedFolderUid_
}
func (sfk *SyncDownSharedFolderKey) KeyType() int32 {
	return sfk.KeyType_
}
func (sfk *SyncDownSharedFolderKey) SharedFolderKey() string {
	return sfk.SharedFolderKey_
}
func (sfk *SyncDownSharedFolderKey) EncryptorUid() string {
	return sfk.encryptorUid
}
func (sfk *SyncDownSharedFolderKey) SubjectUid() string {
	return sfk.SharedFolderUid()
}
func (sfk *SyncDownSharedFolderKey) ObjectUid() string {
	return sfk.EncryptorUid()
}

// Storage shared folder
func (sf *SyncDownSharedFolder) SharedFolderUid() string {
	return sf.SharedFolderUid_
}
func (sf *SyncDownSharedFolder) Revision() int64 {
	return sf.Revision_
}
func (sf *SyncDownSharedFolder) Name() string {
	return sf.Name_
}
func (sf *SyncDownSharedFolder) DefaultCanEdit() bool {
	return sf.DefaultCanEdit_
}
func (sf *SyncDownSharedFolder) DefaultCanShare() bool {
	return sf.DefaultCanShare_
}
func (sf *SyncDownSharedFolder) DefaultManageRecords() bool {
	return sf.DefaultManageRecords_
}
func (sf *SyncDownSharedFolder) DefaultManageUsers() bool {
	return sf.DefaultManageUsers_
}
func (sf *SyncDownSharedFolder) Uid() string {
	return sf.SharedFolderUid()
}

// Storage teams
func (t *SyncDownTeam) TeamUid() string {
	return t.TeamUid_
}
func (t *SyncDownTeam) Name() string {
	return t.Name_
}
func (t *SyncDownTeam) TeamPrivateKey() string {
	return t.TeamPrivateKey_
}
func (t *SyncDownTeam) RestrictEdit() bool {
	return t.RestrictEdit_
}
func (t *SyncDownTeam) RestrictShare() bool {
	return t.RestrictShare_
}
func (t *SyncDownTeam) RestrictView() bool {
	return t.RestrictView_
}
func (t *SyncDownTeam) Uid() string {
	return t.TeamUid()
}
func (t *SyncDownTeam) EncryptorUid() string {
	return t.encryptorUid
}
func (rmd *SyncDownTeam) KeyType() int32 {
	return rmd.TeamKeyType_
}
func (rmd *SyncDownTeam) TeamKey() string {
	return rmd.TeamKey_
}
func (rmd *SyncDownTeam) SubjectUid() string {
	return rmd.TeamUid_
}
func (rmd *SyncDownTeam) ObjectUid() string {
	return rmd.encryptorUid
}

// Storage Record Meta Data
func (rmd *SyncDownRecordMetaData) RecordUid() string {
	return rmd.RecordUid_
}
func (rmd *SyncDownRecordMetaData) KeyType() int32 {
	return rmd.RecordKeyType_
}
func (rmd *SyncDownRecordMetaData) RecordKey() string {
	return rmd.RecordKey_
}
func (rmd *SyncDownRecordMetaData) EncryptorUid() string {
	return rmd.encryptorUid
}
func (rmd *SyncDownRecordMetaData) CanShare() bool {
	return rmd.CanShare_
}
func (rmd *SyncDownRecordMetaData) CanEdit() bool {
	return rmd.CanEdit_
}
func (rmd *SyncDownRecordMetaData) SubjectUid() string {
	return rmd.RecordUid()
}
func (rmd *SyncDownRecordMetaData) ObjectUid() string {
	return rmd.EncryptorUid()
}

//Storage for Records
func (r *SyncDownRecord) RecordUid() string {
	return r.RecordUid_
}
func (r *SyncDownRecord) Revision() int64 {
	return r.Revision_
}
func (r *SyncDownRecord) Version() int32 {
	return r.Version_
}
func (r *SyncDownRecord) ClientModifiedTime() int64 {
	return r.ClientModifiedTime_
}
func (r *SyncDownRecord) Data() string {
	return r.Data_
}
func (r *SyncDownRecord) Extra() string {
	return r.Extra_
}
func (r *SyncDownRecord) UData() string {
	return r.udata
}
func (r *SyncDownRecord) Shared() bool {
	return r.Shared_
}
func (r *SyncDownRecord) Owner() bool {
	return r.owner
}
func (r *SyncDownRecord) SetOwner(value bool) {
	r.owner = value
}
func (r *SyncDownRecord) Uid() string {
	return r.RecordUid()
}
func (r *SyncDownRecord) AdjustUdata() {
	if r.Udata_ != nil {
		if data, err := json.Marshal(r.Udata_); err == nil {
			r.udata = string(data)
		}
	}
}



// Storage for Non Shared Data
func (nsd *SyncDownNonSharedData) RecordUid() string {
	return nsd.RecordUid_
}
func (nsd *SyncDownNonSharedData) Data() string {
	return nsd.Data_
}
func (nsd *SyncDownNonSharedData) Uid() string {
	return nsd.RecordUid()
}

