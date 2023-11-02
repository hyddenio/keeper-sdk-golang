package sqlite

import (
	"flag"
  "testing"

  "gotest.tools/assert"
	"keepersecurity.com/sdk/vault"
	"keepersecurity.com/sqldb"
)

const (
	testUsername = "test@company.com"
)

func TestSqliteVaultStorage(t *testing.T) {
	_ = flag.Lookup("stderrthreshold").Value.Set("WARNING")
	var err error
	var db sqldb.Database
	db, err = OpenSqliteDatabase("file::memory:?cache=shared")
	var storage vault.IVaultStorage
	storage, err = sqldb.NewMultitenantStorage(db, testUsername, "TEST")
	assert.Assert(t, err == nil, err)
	storage.Clear()

	var v vault.Vault
	v, _ = vault.NewMockVault(storage)
	_ = v.SyncDown()
	assert.Assert(t, v.RecordCount() == 3)
	assert.Assert(t, v.SharedFolderCount() == 1)
	assert.Assert(t, v.TeamCount() == 1)
}
