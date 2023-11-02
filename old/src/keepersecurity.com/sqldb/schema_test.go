package sqldb

import (
	"gotest.tools/assert"
  "keepersecurity.com/sdk/vault"

  "reflect"
  "testing"
)

func TestVaultSchema(t *testing.T) {
	var eSchema EntitySchema
	var err error
	var entity interface{}
	var value reflect.Value
	var ok bool

	eSchema, err = CreateRecordEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, eSchema.GetUidField() != nil)
	value, err = eSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageRecord)
	assert.Assert(t, ok)

	eSchema, err = CreateNonSharedDataEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, eSchema.GetUidField() != nil)
	value, err = eSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageNonSharedData)
	assert.Assert(t, ok)

	eSchema, err = CreateSharedFolderEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, eSchema.GetUidField() != nil)
	value, err = eSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageSharedFolder)
	assert.Assert(t, ok)

	eSchema, err = CreateTeamEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, eSchema.GetUidField() != nil)
	value, err = eSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageTeam)
	assert.Assert(t, ok)

	eSchema, err = CreateFolderEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, eSchema.GetUidField() != nil)
	value, err = eSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageFolder)
	assert.Assert(t, ok)

	var lSchema LinkSchema

	lSchema, err = CreateRecordKeySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, lSchema.GetSubjectField() != nil)
	assert.Assert(t, lSchema.GetObjectField() != nil)
	value, err = lSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageRecordKey)
	assert.Assert(t, ok)

	lSchema, err = CreateSharedFolderKeySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, lSchema.GetSubjectField() != nil)
	assert.Assert(t, lSchema.GetObjectField() != nil)
	value, err = lSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageSharedFolderKey)
	assert.Assert(t, ok)

	lSchema, err = CreateSharedFolderPermissionSchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, lSchema.GetSubjectField() != nil)
	assert.Assert(t, lSchema.GetObjectField() != nil)
	value, err = lSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageSharedFolderPermission)
	assert.Assert(t, ok)

	lSchema, err = CreateTeamKeySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, lSchema.GetSubjectField() != nil)
	assert.Assert(t, lSchema.GetObjectField() != nil)
	value, err = lSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageTeamKey)
	assert.Assert(t, ok)

	lSchema, err = CreateFolderRecordSchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, lSchema.GetSubjectField() != nil)
	assert.Assert(t, lSchema.GetObjectField() != nil)
	value, err = lSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(vault.IStorageFolderRecord)
	assert.Assert(t, ok)
}
