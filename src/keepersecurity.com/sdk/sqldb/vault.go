package sqldb

import (
	"database/sql"
	"github.com/golang/glog"
	"keepersecurity.com/sdk"
)

type multitenantStorage struct {
	*tenantStorage

	records       sdk.IRecordEntityStorage
	sharedFolders sdk.ISharedFolderEntityStorage
	teams         sdk.ITeamEntityStorage
	nonSharedData sdk.INonSharedDataEntityStorage
	folders       sdk.IFolderEntityStorage

	recordKeys              sdk.IRecordKeysStorage
	sharedFolderKeys        sdk.ISharedFolderKeysStorage
	sharedFolderPermissions sdk.ISharedFolderPermissionsStorage
	teamKeys                sdk.ITeamKeysStorage
	folderRecords           sdk.IFolderRecordsStorage
}
func (storage *multitenantStorage) Records() sdk.IRecordEntityStorage {
	return storage.records
}
func (storage *multitenantStorage) NonSharedData() sdk.INonSharedDataEntityStorage {
	return storage.nonSharedData
}
func (storage *multitenantStorage) SharedFolders() sdk.ISharedFolderEntityStorage {
	return storage.sharedFolders
}
func (storage *multitenantStorage) Teams() sdk.ITeamEntityStorage {
	return storage.teams
}
func (storage *multitenantStorage) Folders() sdk.IFolderEntityStorage {
	return storage.folders
}
func (storage *multitenantStorage) RecordKeys() sdk.IRecordKeysStorage {
	return storage.recordKeys
}
func (storage *multitenantStorage) SharedFolderKeys() sdk.ISharedFolderKeysStorage {
	return storage.sharedFolderKeys
}
func (storage *multitenantStorage) SharedFolderPermissions() sdk.ISharedFolderPermissionsStorage {
	return storage.sharedFolderPermissions
}
func (storage *multitenantStorage) TeamKeys() sdk.ITeamKeysStorage {
	return storage.teamKeys
}
func (storage *multitenantStorage) FolderRecords() sdk.IFolderRecordsStorage {
	return storage.folderRecords
}
func (storage *multitenantStorage) Clear() {
	storage.SetRevision(0)
	storage.records.Clear()
	storage.sharedFolders.Clear()
	storage.teams.Clear()
	storage.nonSharedData.Clear()
	storage.recordKeys.Clear()
	storage.sharedFolderKeys.Clear()
	storage.sharedFolderPermissions.Clear()
	storage.teamKeys.Clear()
	storage.folders.Clear()
	storage.folderRecords.Clear()
}
func (storage *multitenantStorage) PersonalScopeUid() string {
	return storage.tenantStorage.tenantUid
}
func (storage *multitenantStorage) Revision() (revision int64) {
	var rev sql.NullInt64
	var err error
	if err = storage.tenantStorage.getValue(storage.tenantSchema.revisionColumn, &rev); err == nil {
		if rev.Valid {
			revision = rev.Int64
		}
	}
	if err != nil {
		glog.Warning("Revision error: ", err)
	}
	return
}
func (storage *multitenantStorage) SetRevision(value int64)  {
	if err := storage.tenantStorage.setValue(storage.tenantSchema.revisionColumn, value); err != nil {
		glog.Warning("SetRevision error: ", err)
	}
}

func NewMultitenantStorage(db Database, username string, environment string) (storage sdk.IVaultStorage, err error) {
	var tenant *tenantStorage
	if tenant, err = newTenantStorageForEnvironment(db, username,environment); err != nil {
		return
	}

	var entitySchema EntitySchema

	var recordStorage *sqlEntityStorage
	if entitySchema, err = CreateRecordEntitySchema(); err == nil {
		entitySchema.SetTableName("record")
		if recordStorage, err = createSqlEntity(db, entitySchema, tenant); err == nil {
			err = recordStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var sharedFolderStorage *sqlEntityStorage
	if entitySchema, err = CreateSharedFolderEntitySchema(); err == nil {
		entitySchema.SetTableName("shared_folder")
		if sharedFolderStorage, err = createSqlEntity(db, entitySchema, tenant); err == nil {
			err = sharedFolderStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var teamStorage *sqlEntityStorage
	if entitySchema, err = CreateTeamEntitySchema(); err == nil {
		entitySchema.SetTableName("team")
		if teamStorage, err = createSqlEntity(db, entitySchema, tenant); err == nil {
			err = teamStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var nsdStorage *sqlEntityStorage
	if entitySchema, err = CreateNonSharedDataEntitySchema(); err == nil {
		entitySchema.SetTableName("non_shared_data")
		if nsdStorage, err = createSqlEntity(db, entitySchema, tenant); err == nil {
			err = nsdStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var folderStorage *sqlEntityStorage
	if entitySchema, err = CreateFolderEntitySchema(); err == nil {
		entitySchema.SetTableName("folder")
		if folderStorage, err = createSqlEntity(db, entitySchema, tenant); err == nil {
			err = folderStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var linkSchema LinkSchema

	var recordKeyStorage *sqlLinkStorage
	if linkSchema, err = CreateRecordKeySchema(); err == nil {
		linkSchema.SetTableName("record_key")
		if recordKeyStorage, err = createSqlLink(db, linkSchema, tenant); err == nil {
			err = recordKeyStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var sharedFolderKeyStorage *sqlLinkStorage
	if linkSchema, err = CreateSharedFolderKeySchema(); err == nil {
		linkSchema.SetTableName("shared_folder_key")
		if sharedFolderKeyStorage, err = createSqlLink(db, linkSchema, tenant); err == nil {
			err = sharedFolderKeyStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var sharedFolderPermissionStorage *sqlLinkStorage
	if linkSchema, err = CreateSharedFolderPermissionSchema(); err == nil {
		linkSchema.SetTableName("shared_folder_permission")
		if sharedFolderPermissionStorage, err = createSqlLink(db, linkSchema, tenant); err == nil {
			err = sharedFolderPermissionStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var teamKeyStorage *sqlLinkStorage
	if linkSchema, err = CreateTeamKeySchema(); err == nil {
		linkSchema.SetTableName("team_key")
		if teamKeyStorage, err = createSqlLink(db, linkSchema, tenant); err == nil {
			err = teamKeyStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	var folderRecordStorage *sqlLinkStorage
	if linkSchema, err = CreateFolderRecordSchema(); err == nil {
		linkSchema.SetTableName("folder_record")
		if folderRecordStorage, err = createSqlLink(db, linkSchema, tenant); err == nil {
			err = folderRecordStorage.Verify()
		}
	}
	if err != nil {
		return
	}

	storage = &multitenantStorage{
		tenantStorage:           tenant,
		records:                 sdk.NewRecordEntityStorage(recordStorage),
		sharedFolders:           sdk.NewSharedFolderEntityStorage(sharedFolderStorage),
		teams:                   sdk.NewTeamEntityStorage(teamStorage),
		nonSharedData:           sdk.NewNonSharedDataEntityStorage(nsdStorage),
		folders:                 sdk.NewFolderEntityStorage(folderStorage),
		recordKeys:              sdk.NewRecordKeyLinkStorage(recordKeyStorage),
		sharedFolderKeys:        sdk.NewSharedFolderKeyLinkStorage(sharedFolderKeyStorage),
		sharedFolderPermissions: sdk.NewSharedFolderPermissionLinkStorage(sharedFolderPermissionStorage),
		teamKeys:                sdk.NewTeamKeyLinkStorage(teamKeyStorage),
		folderRecords:           sdk.NewFolderRecordLinkStorage(folderRecordStorage),
	}
	return
}

