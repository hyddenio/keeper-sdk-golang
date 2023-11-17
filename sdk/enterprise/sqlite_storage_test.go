package enterprise

import (
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/sdk/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
	"reflect"
	"testing"
)

func TestExtract(t *testing.T) {
	var entityType = reflect.TypeOf((*EnterpriseEntityData)(nil))
	var ts, err = sqlite.LoadTableSchema(entityType, []string{"type", "key"}, nil,
		"enterprise_id", sqlite.SqlDataType_Integer)
	//var connectionString = "file:///Users/skolupaev/.keeper/keeper_test_db.sqlite?cache=shared&mode=rwc"
	var connectionString = "file::memory:?cache=shared&mode=memory"
	var db *sqlx.DB
	db, err = sqlx.Connect("sqlite3", connectionString)
	assert.NilError(t, err)
	var queries []string
	queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{ts}, true)
	assert.Check(t, len(queries) == 0)

	var eedStorage storage.ILinkStorage[*EnterpriseEntityData, int64, string]
	eedStorage, err = sqlite.NewSqliteLinkStorage[*EnterpriseEntityData, int64, string](
		func() *sqlx.DB { return db }, ts, 12345)
	var es []*EnterpriseEntityData
	var eed = &EnterpriseEntityData{
		Type: 10,
		Key:  "qqqqqq",
		Data: []byte("fdsfdsfdsfdsfdsfsdfdssd"),
	}
	es = append(es, eed)
	err = eedStorage.PutLinks(es)
	assert.NilError(t, err)
	es = nil
	err = eedStorage.GetAll(func(data *EnterpriseEntityData) bool {
		es = append(es, data)
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, len(es) == 1)

	es = nil
	err = eedStorage.GetLinksForSubjects([]int64{10}, func(data *EnterpriseEntityData) bool {
		es = append(es, data)
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, len(es) == 1)

	es = nil
	err = eedStorage.GetLinksForObjects([]string{"qqqqqq"}, func(data *EnterpriseEntityData) bool {
		es = append(es, data)
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, len(es) == 1)

	var eed1 *EnterpriseEntityData
	eed1, err = eedStorage.GetLink(10, "qqqqqq")
	assert.NilError(t, err)
	assert.Check(t, eed1.Type == 10)

	err = eedStorage.DeleteLinks([]storage.IUidLink[int64, string]{storage.NewUidLink[int64, string](10, "qqqqqq")})
	assert.NilError(t, err)

	eed1, err = eedStorage.GetLink(10, "qqqqqq")
	assert.NilError(t, err)
	assert.Check(t, eed1 == nil)
}
