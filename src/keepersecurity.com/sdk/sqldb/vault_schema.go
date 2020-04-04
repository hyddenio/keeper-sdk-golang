package sqldb

import (
	"errors"
	"fmt"
	"keepersecurity.com/sdk"
	"reflect"
)

type entitySchema struct {
	baseSchema
	uidField  Field
}
func (es *entitySchema) GetUidField() Field {
	return es.uidField
}

func extractEntitySchema(entityType reflect.Type) (schema EntitySchema, err error) {
	var extractInfo *masterExtractInfo
	if extractInfo, err = extractMasterFields(entityType); err != nil {
		return
	}
	if len(extractInfo.children) > 0 {
		err = errors.New("vault entity does not support child scopes")
		return
	}

	var columns = extractInfo.fields
	if !entityType.Implements(reflect.TypeOf((*Initializer)(nil)).Elem()) {
		err = errors.New(fmt.Sprintf("%s: should implement Initializer interface", entityType.Name()))
		return
	}

	if !entityType.Implements(reflect.TypeOf((*sdk.IUid)(nil)).Elem()) {
		err = errors.New(fmt.Sprintf("%s: should implement IUid interface", entityType.Name()))
		return
	}

	eSchema := new(entitySchema)
	eSchema.rowType = entityType

	for _, f := range columns {
		if f.HasKey("uid") {
			if eSchema.uidField != nil {
				err = errors.New(fmt.Sprintf("%s: multiple uid columns", entityType.Name()))
				return
			}
			f.SetPrecision(64)
			eSchema.uidField = f
		} else {
			eSchema.dataFields = append(eSchema.dataFields, f)
		}
	}

	if eSchema.uidField == nil {
		err = errors.New(fmt.Sprintf("%s: uid column not found", entityType.Name()))
	}
	schema = eSchema
	return
}

type linkSchema struct {
	baseSchema
	subjectField  Field
	objectField  Field
}
func (ls *linkSchema) GetSubjectField() Field {
	return ls.subjectField
}
func (ls *linkSchema) GetObjectField() Field {
	return ls.objectField
}

func extractLinkSchema(linkType reflect.Type) (schema LinkSchema, err error) {
	var extractInfo *masterExtractInfo
	if extractInfo, err = extractMasterFields(linkType); err != nil {
		return
	}
	if len(extractInfo.children) > 0 {
		err = errors.New("vault link does not support child scopes")
		return
	}

	var columns = extractInfo.fields

	lSchema := new(linkSchema)
	lSchema.rowType = linkType

	for _, f := range columns {
		if f.HasKey("subject") {
			if lSchema.subjectField != nil {
				err = errors.New(fmt.Sprintf("%s: multiple subject_uid columns", linkType.Name()))
				return
			}
			f.SetPrecision(64)
			lSchema.subjectField = f
		} else if f.HasKey("object") {
			if lSchema.objectField != nil {
				err = errors.New(fmt.Sprintf("%s: multiple object_uid columns", linkType.Name()))
				return
			}
			f.SetPrecision(64)
			lSchema.objectField = f
		} else {
			lSchema.dataFields = append(lSchema.dataFields, f)
		}
	}

	if lSchema.subjectField == nil {
		err = errors.New(fmt.Sprintf("%s: subject column not found", linkType.Name()))
	}
	if lSchema.objectField == nil {
		err = errors.New(fmt.Sprintf("%s: object column not found", linkType.Name()))
	}
	schema = lSchema
	return
}

func CreateRecordEntitySchema() (schema EntitySchema, err error) {
	return extractEntitySchema(reflect.TypeOf((*recordStorage)(nil)))
}
func CreateNonSharedDataEntitySchema() (schema EntitySchema, err error) {
	return extractEntitySchema(reflect.TypeOf((*nonSharedDataStorage)(nil)))
}
func CreateSharedFolderEntitySchema() (schema EntitySchema, err error) {
	return extractEntitySchema(reflect.TypeOf((*sharedFolderStorage)(nil)))
}
func CreateTeamEntitySchema() (schema EntitySchema, err error) {
	return extractEntitySchema(reflect.TypeOf((*teamStorage)(nil)))
}
func CreateFolderEntitySchema() (schema EntitySchema, err error) {
	return extractEntitySchema(reflect.TypeOf((*folderStorage)(nil)))
}
func CreateRecordKeySchema() (schema LinkSchema, err error) {
	return extractLinkSchema(reflect.TypeOf((*recordKeyStorage)(nil)))
}
func CreateSharedFolderKeySchema() (schema LinkSchema, err error) {
	return extractLinkSchema(reflect.TypeOf((*sharedFolderKeyStorage)(nil)))
}
func CreateSharedFolderPermissionSchema() (schema LinkSchema, err error) {
	return extractLinkSchema(reflect.TypeOf((*sharedFolderPermissionStorage)(nil)))
}
func CreateTeamKeySchema() (schema LinkSchema, err error) {
	return extractLinkSchema(reflect.TypeOf((*teamKeyStorage)(nil)))
}
func CreateFolderRecordSchema() (schema LinkSchema, err error) {
	return extractLinkSchema(reflect.TypeOf((*folderRecordStorage)(nil)))
}



