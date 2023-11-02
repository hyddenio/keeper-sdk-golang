package vault

import (
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
	"gotest.tools/assert"
	"testing"
	"time"
)

func TestEntityStorage(t *testing.T) {
	var recordStorage = storage.NewInMemoryEntityStorage[[]byte, IStorageRecord]()
	var uid = api.GenerateUid()
	var r = &RecordStorage{
		RecordUid_:    uid,
		Revision_:     1000_000_000,
		Version_:      3,
		ClientTime_:   time.Now().UnixMilli(),
		Data_:         []byte("DATA"),
		Extra_:        nil,
		UData_:        nil,
		Shared_:       false,
		Owner_:        true,
		OwnerAccount_: api.GetRandomBytes(16),
	}

	var err = recordStorage.PutEntities([]IStorageRecord{r})
	assert.NilError(t, err)
	var r1 IStorageRecord
	r1, err = recordStorage.GetEntity(uid)
	assert.NilError(t, err)
	assert.Assert(t, r == r1)
	err = recordStorage.DeleteUids([][]byte{uid, uid})
	assert.NilError(t, err)
}
