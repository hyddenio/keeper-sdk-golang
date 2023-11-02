package vault

import (
  "gotest.tools/assert"
  "keepersecurity.com/sdk/auth"

  "testing"
)

func TestVault_SyncDown(t *testing.T) {
  v, _ := NewMockVault(NewInMemoryVaultStorage())
  _ = v.SyncDown()
  assert.Assert(t, v.RecordCount() == 3)
  assert.Assert(t, v.SharedFolderCount() == 1)
  assert.Assert(t, v.TeamCount() == 1)
}
func TestVault_SyncDownRemoveOwnedRecord(t *testing.T) {
  v, authMmock := NewMockVault(NewInMemoryVaultStorage())
  _ = v.SyncDown()
  recordsBefore := v.RecordCount()
  toRemove := make([]string, 0)
  v.VaultStorage().Records().Enumerate(func(sr IStorageRecord) bool {
    if sr.Owner() {
      toRemove = append(toRemove, sr.RecordUid())
    }
    return true
  })
  revision := v.VaultStorage().Revision() + 10
  authMmock.MockSyncDownResponse = &SyncDownResponse{
    KeeperApiResponse: auth.KeeperApiResponse{
      Result: "success",
    },
    FullSync:       false,
    Revision:       revision,
    RemovedRecords: toRemove,
  }
  _ = v.SyncDown()

  assert.Assert(t, v.RecordCount() == recordsBefore-len(toRemove))
  assert.Assert(t, v.SharedFolderCount() == 1)
  assert.Assert(t, v.TeamCount() == 1)
  assert.Assert(t, v.VaultStorage().Revision() == revision)
}

func TestVault_SyncDownRemoveTeam(t *testing.T) {
  v, authMock := NewMockVault( NewInMemoryVaultStorage())
  _ = v.SyncDown()

  recordsBefore := v.RecordCount()
  sharedFoldersBefore := v.SharedFolderCount()

  toRemove := make([]string, 0)
  v.GetAllTeams(func (t *EnterpriseTeam) bool {
    toRemove = append(toRemove, t.TeamUid)
    return true
  })

  revision := v.VaultStorage().Revision() + 10
  authMock.MockSyncDownResponse = &SyncDownResponse{
    KeeperApiResponse: auth.KeeperApiResponse{
      Result: "success",
    },
    FullSync:     false,
    Revision:     revision,
    RemovedTeams: toRemove,
  }
  _ = v.SyncDown()

  assert.Assert(t, v.RecordCount() == recordsBefore)
  assert.Assert(t, v.SharedFolderCount() == sharedFoldersBefore)
  assert.Assert(t, v.TeamCount() == 0)
}

func TestVault_SyncDownRemoveSharedFolderThenTeam(t *testing.T) {
  v, authMmock := NewMockVault(NewInMemoryVaultStorage())
  _ = v.SyncDown()

  recordsBefore := v.RecordCount()
  sharedFoldersBefore := v.SharedFolderCount()
  teamsBefore := v.TeamCount()

  toRemove := make([]string, 0)
  v.GetAllSharedFolders(func (sf *SharedFolder) bool {
    toRemove = append(toRemove, sf.SharedFolderUid)
    return true
  })

  revision := v.VaultStorage().Revision() + 10
  authMmock.MockSyncDownResponse = &SyncDownResponse{
    KeeperApiResponse: auth.KeeperApiResponse{
      Result: "success",
    },
    FullSync:     false,
    Revision:     revision,
    RemovedSharedFolders: toRemove,
  }
  _ = v.SyncDown()
  assert.Assert(t, v.RecordCount() == recordsBefore)
  assert.Assert(t, v.SharedFolderCount() == sharedFoldersBefore)
  assert.Assert(t, v.TeamCount() == teamsBefore)


  recordsBefore = v.RecordCount()
  sharedFoldersBefore = v.SharedFolderCount()
  teamsBefore = v.TeamCount()

  toRemove = make([]string, 0)
  v.GetAllTeams(func (t *EnterpriseTeam) bool {
    toRemove = append(toRemove, t.TeamUid)
    return true
  })

  revision = v.VaultStorage().Revision() + 10
  authMmock.MockSyncDownResponse = &SyncDownResponse{
    KeeperApiResponse: auth.KeeperApiResponse{
      Result: "success",
    },
    FullSync:     false,
    Revision:     revision,
    RemovedTeams: toRemove,
  }
  _ = v.SyncDown()

  assert.Assert(t, v.RecordCount() == 2)
  assert.Assert(t, v.SharedFolderCount() == 0)
  assert.Assert(t, v.TeamCount() == 0)
}

func TestVault_SyncDownRemoveSharedFolderAndTeam(t *testing.T) {
  v, authMmock := NewMockVault(NewInMemoryVaultStorage())
  _ = v.SyncDown()

  sfToRemove := make([]string, 0)
  v.GetAllSharedFolders(func(sf *SharedFolder) bool {
    sfToRemove = append(sfToRemove, sf.SharedFolderUid)
    return true
  })

  teamToRemove := make([]string, 0)
  v.GetAllTeams(func (t *EnterpriseTeam) bool {
    teamToRemove = append(teamToRemove, t.TeamUid)
    return true
  })

  revision := v.VaultStorage().Revision() + 10
  authMmock.MockSyncDownResponse = &SyncDownResponse{
    KeeperApiResponse: auth.KeeperApiResponse{
      Result: "success",
    },
    FullSync:             false,
    Revision:             revision,
    RemovedSharedFolders: sfToRemove,
    RemovedTeams:         teamToRemove,
  }
  _ = v.SyncDown()
  assert.Assert(t, v.RecordCount() == 2)
  assert.Assert(t, v.SharedFolderCount() == 0)
  assert.Assert(t, v.TeamCount() == 0)
}
