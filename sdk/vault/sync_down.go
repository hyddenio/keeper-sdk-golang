package vault

import (
	"bytes"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_sync_down"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
)

var (
	_ RebuildTask = new(rebuildTask)
)

type UID = [16]byte

type RebuildTask interface {
	IsFullSync() bool
	Records() map[UID]bool
	SharedFolders() map[UID]bool
	AddRecords([][]byte)
	AddSharedFolders([][]byte)
}

type rebuildTask struct {
	isFullSync    bool
	records       map[UID]bool
	sharedFolders map[UID]bool
}

func (rt *rebuildTask) IsFullSync() bool {
	return rt.isFullSync
}
func (rt *rebuildTask) Records() map[UID]bool {
	return rt.records
}
func (rt *rebuildTask) SharedFolders() map[UID]bool {
	return rt.sharedFolders
}
func (rt *rebuildTask) AddRecords(recordUIDs [][]byte) {
	if rt.isFullSync {
		return
	}
	if rt.records == nil {
		rt.records = make(map[UID]bool)
	}
	var uid UID
	for _, recordUID := range recordUIDs {
		copy(uid[:], recordUID)
		rt.records[uid] = true
	}
}
func (rt *rebuildTask) AddSharedFolders(sharedFolderUIDs [][]byte) {
	if rt.isFullSync {
		return
	}
	if rt.sharedFolders == nil {
		rt.sharedFolders = make(map[UID]bool)
	}
	var uid UID
	for _, sharedFolderUID := range sharedFolderUIDs {
		copy(uid[:], sharedFolderUID)
		rt.sharedFolders[uid] = true
	}
}

func syncDownRequest(keeperAuth auth.IKeeperAuth, vaultStorage IVaultStorage, syncRecordTypes bool) (task RebuildTask, err error) {
	var logger = api.GetLogger()
	var emailLookup = make(map[string]string)

	var rqSync = &proto_sync_down.SyncDownRequest{}
	var done = false
	var token = vaultStorage.ContinuationToken()
	for !done {
		rqSync.ContinuationToken = token
		var rsSync = &proto_sync_down.SyncDownResponse{}
		if err = keeperAuth.ExecuteAuthRest("vault/sync_down", rqSync, rsSync); err != nil {
			return
		}
		done = rsSync.HasMore
		token = rsSync.ContinuationToken
		if rsSync.CacheStatus == proto_sync_down.CacheStatus_CLEAR {
			syncRecordTypes = true
			vaultStorage.Clear()
			logger.Debug("Full Sync")
		}
		if task == nil {
			task = &rebuildTask{
				isFullSync: rsSync.CacheStatus == proto_sync_down.CacheStatus_CLEAR,
			}
		}
		var er1 error
		var uid UID
		var uids [][]byte
		var links []storage.IUidLink[[]byte, []byte]
		if len(rsSync.RemovedRecords) > 0 {
			task.AddRecords(rsSync.RemovedRecords)
			links = nil
			for _, x := range rsSync.RemovedRecords {
				links = append(links, storage.NewUidLink(x, vaultStorage.PersonalScopeUid()))
			}
			if err = vaultStorage.RecordKeys().DeleteLinks(links); err != nil {
				return
			}
			var folderUIDs = make(map[UID]*bool)
			links = nil
			if err = vaultStorage.FolderRecords().GetLinksForObjects(rsSync.RemovedRecords, func(record IStorageFolderRecord) bool {
				links = append(links, record)
				copy(uid[:], record.SubjectUid())
				folderUIDs[uid] = new(bool)
				return true
			}); err != nil {
				return
			}
			for k, v := range folderUIDs {
				var u = k[:]
				if bytes.Equal(u, vaultStorage.PersonalScopeUid()) {
					*v = true
				} else {
					var folder IStorageFolder
					if folder, er1 = vaultStorage.Folders().GetEntity(u); er1 == nil {
						if folder != nil && folder.FolderType() == "user_folder" {
							*v = true
						}
					}
				}
			}
			var last = len(links) - 1
			for i, x := range links {
				if x == nil {
					break
				}
				copy(uid[:], x.SubjectUid())
				var keep, _ = folderUIDs[uid]
				if keep != nil && *keep {
					continue
				}
				links[i] = links[last]
				links[last] = nil
				last--
			}
			if last < len(links)-1 {
				links = links[:last+1]
			}
			if err = vaultStorage.FolderRecords().DeleteLinks(links); err != nil {
				return
			}
		}
	}

	return
}
