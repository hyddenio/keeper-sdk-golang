package mock

import (
	"gotest.tools/assert"
	"keepersecurity.com/sdk"
	"testing"
)

func TestVault_SyncDown(t *testing.T) {
	vault, _ := NewMockVault(sdk.NewInMemoryVaultStorage())
	_ = vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == 3)
	assert.Assert(t, vault.SharedFolderCount() == 1)
	assert.Assert(t, vault.TeamCount() == 1)
}

func TestVault_SyncDownRemoveOwnedRecord(t *testing.T) {
	vault, authMmock := NewMockVault( sdk.NewInMemoryVaultStorage())
	_ = vault.SyncDown()
	recordsBefore := vault.RecordCount()
	toRemove := make([]string, 0)
	vault.VaultStorage().Records().Enumerate(func(sr sdk.IStorageRecord) bool {
		if sr.Owner() {
			toRemove = append(toRemove, sr.RecordUid())
		}
		return true
	})
	revision := vault.VaultStorage().Revision() + 10
	authMmock.MockSyncDownResponse = &sdk.SyncDownResponse{
		KeeperApiResponse: sdk.KeeperApiResponse{
			Result: "success",
		},
		FullSync:       false,
		Revision:       revision,
		RemovedRecords: toRemove,
	}
	_ = vault.SyncDown()

	assert.Assert(t, vault.RecordCount() == recordsBefore-len(toRemove))
	assert.Assert(t, vault.SharedFolderCount() == 1)
	assert.Assert(t, vault.TeamCount() == 1)
	assert.Assert(t, vault.VaultStorage().Revision() == revision)
}

func TestVault_SyncDownRemoveTeam(t *testing.T) {
	vault, authMmock := NewMockVault( sdk.NewInMemoryVaultStorage())
	_ = vault.SyncDown()

	recordsBefore := vault.RecordCount()
	sharedFoldersBefore := vault.SharedFolderCount()

	toRemove := make([]string, 0)
	vault.GetAllTeams(func (t *sdk.EnterpriseTeam) bool {
		toRemove = append(toRemove, t.TeamUid)
		return true
	})

	revision := vault.VaultStorage().Revision() + 10
	authMmock.MockSyncDownResponse = &sdk.SyncDownResponse{
		KeeperApiResponse: sdk.KeeperApiResponse{
			Result: "success",
		},
		FullSync:     false,
		Revision:     revision,
		RemovedTeams: toRemove,
	}
	_ = vault.SyncDown()

	assert.Assert(t, vault.RecordCount() == recordsBefore)
	assert.Assert(t, vault.SharedFolderCount() == sharedFoldersBefore)
	assert.Assert(t, vault.TeamCount() == 0)
}

func TestVault_SyncDownRemoveSharedFolderThenTeam(t *testing.T) {
	vault, authMmock := NewMockVault( sdk.NewInMemoryVaultStorage())
	_ = vault.SyncDown()

	recordsBefore := vault.RecordCount()
	sharedFoldersBefore := vault.SharedFolderCount()
	teamsBefore := vault.TeamCount()

	toRemove := make([]string, 0)
	vault.GetAllSharedFolders(func (sf *sdk.SharedFolder) bool {
		toRemove = append(toRemove, sf.SharedFolderUid)
		return true
	})

	revision := vault.VaultStorage().Revision() + 10
	authMmock.MockSyncDownResponse = &sdk.SyncDownResponse{
		KeeperApiResponse: sdk.KeeperApiResponse{
			Result: "success",
		},
		FullSync:     false,
		Revision:     revision,
		RemovedSharedFolders: toRemove,
	}
	_ = vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == recordsBefore)
	assert.Assert(t, vault.SharedFolderCount() == sharedFoldersBefore)
	assert.Assert(t, vault.TeamCount() == teamsBefore)


	recordsBefore = vault.RecordCount()
	sharedFoldersBefore = vault.SharedFolderCount()
	teamsBefore = vault.TeamCount()

	toRemove = make([]string, 0)
	vault.GetAllTeams(func (t *sdk.EnterpriseTeam) bool {
		toRemove = append(toRemove, t.TeamUid)
		return true
	})

	revision = vault.VaultStorage().Revision() + 10
	authMmock.MockSyncDownResponse = &sdk.SyncDownResponse{
		KeeperApiResponse: sdk.KeeperApiResponse{
			Result: "success",
		},
		FullSync:     false,
		Revision:     revision,
		RemovedTeams: toRemove,
	}
	_ = vault.SyncDown()

	assert.Assert(t, vault.RecordCount() == 2)
	assert.Assert(t, vault.SharedFolderCount() == 0)
	assert.Assert(t, vault.TeamCount() == 0)
}

func TestVault_SyncDownRemoveSharedFolderAndTeam(t *testing.T) {
	vault, authMmock := NewMockVault( sdk.NewInMemoryVaultStorage())
	_ = vault.SyncDown()

	sfToRemove := make([]string, 0)
	vault.GetAllSharedFolders(func(sf *sdk.SharedFolder) bool {
		sfToRemove = append(sfToRemove, sf.SharedFolderUid)
		return true
	})

	teamToRemove := make([]string, 0)
	vault.GetAllTeams(func (t *sdk.EnterpriseTeam) bool {
		teamToRemove = append(teamToRemove, t.TeamUid)
		return true
	})

	revision := vault.VaultStorage().Revision() + 10
	authMmock.MockSyncDownResponse = &sdk.SyncDownResponse{
		KeeperApiResponse: sdk.KeeperApiResponse{
			Result: "success",
		},
		FullSync:             false,
		Revision:             revision,
		RemovedSharedFolders: sfToRemove,
		RemovedTeams:         teamToRemove,
	}
	_ = vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == 2)
	assert.Assert(t, vault.SharedFolderCount() == 0)
	assert.Assert(t, vault.TeamCount() == 0)
}
