package vault

import (
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
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
	assert.Assert(t, len(queries) > 0)

	var ees storage.IEntityStorage[IStorageRecord, string]
	ees, err = sqlite.NewSqliteEntityStorage[IStorageRecord, string](func() *sqlx.DB { return db }, ts, []byte("xxx"))
	var recordUid = api.Base64UrlEncode(api.GenerateUid())
	var r = &RecordStorage{
		RecordUid_:    recordUid,
		ClientTime_:   3232320,
		Data_:         []byte("DATA"),
		Extra_:        nil,
		UData_:        nil,
		Owner_:        false,
		OwnerAccount_: api.Base64UrlEncode(api.GenerateUid()),
		Revision_:     3453243543534,
		Shared_:       true,
	}
	err = ees.PutEntities([]IStorageRecord{r})
	var r1 IStorageRecord
	r1, err = ees.GetEntity(recordUid)
	assert.NilError(t, err)
	assert.Check(t, r1 != nil)
}
