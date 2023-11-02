package vault

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/sqlite"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
	"reflect"
	"testing"
)

func TestExtract(t *testing.T) {
	var entityType = reflect.TypeOf((*RecordStorage)(nil))
	var ts, err = sqlite.LoadTableSchema(entityType, []string{"record_uid"}, nil,
		"account_uid", sqlite.SqlDataType_Blob)
	//var connectionString = "file:///Users/skolupaev/.keeper/keeper_db.sqlite?cache=shared&mode=rwc"
	var connectionString = "file::memory:?cache=shared&mode=memory"
	var db *sqlx.DB
	db, err = sqlx.Connect("sqlite3", connectionString)
	assert.NilError(t, err)
	ts.SetTableName("StorageRecord")
	var queries []string
	queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{ts}, true)

	var ees = sqlite.NewSqliteStorage[IStorageRecord](func() *sqlx.DB { return db }, ts, 0)
	var r = &RecordStorage{
		RecordUid_:    api.GenerateUid(),
		ClientTime_:   3232320,
		Data_:         []byte("DATA"),
		Extra_:        nil,
		UData_:        nil,
		Owner_:        false,
		OwnerAccount_: api.GenerateUid(),
		Revision_:     3453243543534,
		Shared_:       true,
	}
	err = ees.Put([]IStorageRecord{r})
	err = ees.SelectFilter([]string{"record_uid"}, [][]interface{}{{r.RecordUid()}}, func(storage IStorageRecord) bool {
		fmt.Printf("%v", storage)
		return true
	})
	assert.NilError(t, err)
	assert.Assert(t, len(queries) > 0)
	assert.Assert(t, ts != nil)
}
