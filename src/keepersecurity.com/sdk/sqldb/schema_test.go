package sqldb

import (
	"gotest.tools/assert"
	"keepersecurity.com/sdk"
	"reflect"
	"testing"
)

func TestRecordSchema(t *testing.T) {
	var entitySchema EntitySchema
	var err error
	var entity interface{}
	var value reflect.Value
	var ok bool

	entitySchema, err = CreateRecordEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, entitySchema.GetUidField() != nil)
	value, err = entitySchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageRecord)
	assert.Assert(t, ok)

	entitySchema, err = CreateNonSharedDataEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, entitySchema.GetUidField() != nil)
	value, err = entitySchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageNonSharedData)
	assert.Assert(t, ok)

	entitySchema, err = CreateSharedFolderEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, entitySchema.GetUidField() != nil)
	value, err = entitySchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageSharedFolder)
	assert.Assert(t, ok)

	entitySchema, err = CreateTeamEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, entitySchema.GetUidField() != nil)
	value, err = entitySchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageTeam)
	assert.Assert(t, ok)

	entitySchema, err = CreateFolderEntitySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, entitySchema.GetUidField() != nil)
	value, err = entitySchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageFolder)
	assert.Assert(t, ok)

	var linkSchema LinkSchema

	linkSchema, err = CreateRecordKeySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, linkSchema.GetSubjectField() != nil)
	assert.Assert(t, linkSchema.GetObjectField() != nil)
	value, err = linkSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageRecordKey)
	assert.Assert(t, ok)

	linkSchema, err = CreateSharedFolderKeySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, linkSchema.GetSubjectField() != nil)
	assert.Assert(t, linkSchema.GetObjectField() != nil)
	value, err = linkSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageSharedFolderKey)
	assert.Assert(t, ok)

	linkSchema, err = CreateSharedFolderPermissionSchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, linkSchema.GetSubjectField() != nil)
	assert.Assert(t, linkSchema.GetObjectField() != nil)
	value, err = linkSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageSharedFolderPermission)
	assert.Assert(t, ok)

	linkSchema, err = CreateTeamKeySchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, linkSchema.GetSubjectField() != nil)
	assert.Assert(t, linkSchema.GetObjectField() != nil)
	value, err = linkSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageTeamKey)
	assert.Assert(t, ok)

	linkSchema, err = CreateFolderRecordSchema()
	assert.Assert(t, err == nil, err)
	assert.Assert(t, linkSchema.GetSubjectField() != nil)
	assert.Assert(t, linkSchema.GetObjectField() != nil)
	value, err = linkSchema.GetRowValue(nil)
	assert.Assert(t, err == nil, err)
	entity = value.Interface()
	_, ok = entity.(sdk.IStorageFolderRecord)
	assert.Assert(t, ok)
}
