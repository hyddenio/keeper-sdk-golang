package sqldb

import (
  "database/sql"
  "errors"
  "fmt"
  "reflect"

  "keepersecurity.com/sdk/vault"
)

type QueryType uint32
const (
	Select QueryType = iota
	Update
	Insert
	Delete
)

type IMasterDetailSchema interface {
	Schema
	MasterField() Field
	GetQuery(Database, QueryType) string
}
type IDetailSchema interface {
	IMasterDetailSchema
	DetailField() Field
	FieldIndex() int
	HasKey(string) bool
}
type IMasterSchema interface {
	IMasterDetailSchema
	Details(func(IDetailSchema)bool)
}

type KeyValueStorage interface {
	Get(interface{}) (interface{}, error)
	Put(interface{}, interface{}) error
	Delete(interface{}) error
}

type masterDetailSchema struct {
	baseSchema
	masterField Field
	queries map[QueryType]string
}
func (s *masterDetailSchema) MasterField() Field {
	return s.masterField
}
type detailSchema struct {
	masterDetailSchema
	detailField Field
	fieldIndex  int
	extraTags   vault.Set
}
func (d *detailSchema) DetailField() Field {
	return d.detailField
}
func (d *detailSchema) FieldIndex() int {
	return d.fieldIndex
}
func (d *detailSchema) HasKey(key string) bool {
	return d.extraTags.IsSet(key)
}

func (d *detailSchema) GetQuery(db Database, qType QueryType) (query string) {
	var ok bool
	var masterColumn = d.masterField.GetColumnName()
	var detailColumn = d.detailField.GetColumnName()
	var dataColumns = make([]string, 0)
	if qType == Select {
		dataColumns = append(dataColumns, detailColumn)
	}
	for _, f := range d.dataFields {
		if qType == Insert || qType == Update {
			if f.HasKey("read-only") {
				continue
			}
		}
		dataColumns = append(dataColumns, f.GetColumnName())
	}
	if query, ok = d.queries[qType]; !ok {
		switch qType {
		case Select:
			query = SelectQuery(db, d.tableName, []string{masterColumn}, dataColumns)
		case Update:
			query = UpdateQuery(db, d.tableName, []string{masterColumn, detailColumn}, dataColumns)
		case Insert:
			query = InsertQuery(db, d.tableName, []string{masterColumn, detailColumn}, dataColumns)
		case Delete:
			query = DeleteQuery(db, d.tableName, []string{masterColumn})
		}
		d.queries[qType] = query
	}
	return
}
type masterSchema struct {
	masterDetailSchema
	details []*detailSchema
}
func (s *masterSchema) GetQuery(db Database, qType QueryType) (query string) {
	var ok bool
	if query, ok = s.queries[qType]; !ok {
		var masterColumn = s.masterField.GetColumnName()
		var dataColumns = make([]string, 0)
		for _, f := range s.dataFields {
			if qType == Insert || qType == Update {
				if f.HasKey("read-only") {
					continue
				}
			}
			dataColumns = append(dataColumns, f.GetColumnName())
		}
		switch qType {
		case Select:
			query = SelectQuery(db, s.tableName, []string {masterColumn}, dataColumns)
		case Update:
			query = UpdateQuery(db, s.tableName, []string {masterColumn}, dataColumns)
		case Insert:
			query = InsertQuery(db, s.tableName, []string {masterColumn}, dataColumns)
		case Delete:
			query = DeleteQuery(db, s.tableName, []string {masterColumn})
		}
		s.queries[qType] = query
	}
	return
}

func (m *masterSchema) Details(callback func(IDetailSchema)bool) {
	for _, d := range m.details {
		if !callback(d) {
			break
		}
	}
}

type masterDetailStorage struct {
	db Database
	schema *masterSchema
}

func (m *masterDetailStorage) getValues(schema IMasterDetailSchema, key interface{}) (values []reflect.Value, err error) {
	var ok bool
	keyFields := []Field {m.schema.masterField}
	var detailSchema IDetailSchema
	if detailSchema, ok = schema.(IDetailSchema); ok {
		keyFields = append(keyFields, detailSchema.DetailField())
	}
	dataFields := make([]Field, 0)
	for _, f := range schema.GetDataFields() {
		dataFields = append(dataFields, f)
	}
	var query = schema.GetQuery(m.db, Select)
	var stmt *sql.Stmt
	if stmt, err = m.db.GetStatement(query); err == nil {
		var rows *sql.Rows
		if rows, err = stmt.Query(key); err == nil {
			for rows.Next() {
				var pValue = schema.CreateRowValue()
				var keyScanner = make([]interface{}, 0)
				for _,f := range keyFields {
					keyScanner = append(keyScanner, f)
				}
				var dataScanner = make([]interface{}, 0)
				for _, f := range dataFields {
					dataScanner = append(dataScanner, f)
				}
				var scanner []interface{}
				if scanner, err = GetScanner(pValue.Elem(), keyScanner, dataScanner); err == nil {
					if err = rows.Scan(scanner...); err == nil {
						values = append(values, pValue)
					} else {
						break
					}
				}
			}
			_ = rows.Close()
		}
		stmt.Close()
	}
	return
}
func (m *masterDetailStorage) Get(key interface{}) (result interface{}, err error) {
	var values []reflect.Value
	if values, err = m.getValues(m.schema, key); err != nil {
		return
	}
	if len(values) != 1 {
		return
	}
	var resultValue = values[0]
	for _, detail := range m.schema.details {
		var detailValues []reflect.Value
		if detailValues, err = m.getValues(detail, key); err != nil {
			return
		}
		var eValue = resultValue.Elem()
		var arv = eValue.Field(detail.fieldIndex)
		if arv.Kind() == reflect.Slice {
			for _, dv := range detailValues {
				if dv.Type() == detail.rowType {
					arv.Set(reflect.Append(arv, dv))
				} else {
					err = errors.New("unexpected detail type")
					break
				}
			}
		} else {
			err = errors.New("slice type expected")
			break
		}
	}
	if err == nil {
		result = resultValue.Interface()
	}
	return
}

func (m *masterDetailStorage) putValue(dataRow reflect.Value, schema IMasterDetailSchema, key interface{}) (err error) {
	var ok bool
	keyFields := []Field {m.schema.masterField}
	var detailSchema IDetailSchema
	if detailSchema, ok = schema.(IDetailSchema); ok {
		keyFields = append(keyFields, detailSchema.DetailField())
	}

	dataFields := make([]Field, 0)
	for _, f := range schema.GetDataFields() {
		if !f.HasKey("read-only") {
			dataFields = append(dataFields, f)
		}
	}

	var query = schema.GetQuery(m.db, Update)
	var keyValues = []interface{} {key}
	if len(keyFields) > 1 {
		keyValues = append(keyValues, keyFields[1])
	}
	var dataValues = make([]interface{}, 0)
	for _, f := range dataFields {
		dataValues = append(dataValues, f)
	}
	var values []interface{}

	var stmt *sql.Stmt
	var updated = false
	if stmt, err = m.db.GetStatement(query); err == nil {
		values, err = GetUpdateValuer(dataRow, keyValues, dataValues)
		var result sql.Result
		if result, err = stmt.Exec(values...); err == nil {
			var affected int64
			if affected, err = result.RowsAffected(); err == nil {
				updated = affected > 0
			}
		}
		stmt.Close()
	}
	if err != nil {
		return
	}
	if !updated {
		query = schema.GetQuery(m.db, Insert)
		if stmt, err = m.db.GetStatement(query); err == nil {
			values, err = GetInsertValuer(dataRow, keyValues, dataValues)
			_, err = stmt.Exec(values...)
			stmt.Close()
		}
	}
	return
}

func (m *masterDetailStorage) Put(key interface{}, value interface{}) (err error) {
	var dataRow reflect.Value
	if dataRow, err = m.schema.GetRowValue(value); err != nil {
		return
	}

	if err = m.putValue(dataRow, m.schema, key); err != nil {
		return
	}
	var eValue = dataRow.Elem()
	for _, detail := range m.schema.details {
		var arv = eValue.Field(detail.FieldIndex())
		if arv.Kind() == reflect.Slice && !arv.IsNil() {
			for i := 0; i < arv.Len(); i++ {
				var dr = arv.Index(i)
				if err = m.putValue(dr, detail, key); err != nil {
					break
				}
			}
		}
	}
	return
}

func (m *masterDetailStorage) deleteKey(schema IMasterDetailSchema, key interface{}) (err error) {
	var query = schema.GetQuery(m.db, Delete)
	var stmt *sql.Stmt
	if stmt, err = m.db.GetStatement(query); err == nil {
		_, err = stmt.Exec(key)
		stmt.Close()
	}
	return
}

func (m *masterDetailStorage) Delete(key interface{}) (err error) {
	for _, detail := range m.schema.details {
		if err = m.deleteKey(detail, key); err != nil {
			break
		}
	}
	if err == nil {
		err = m.deleteKey(m.schema, key)
	}
	return
}

func NewKeyValueStorage(db Database, rowType reflect.Type, tableName string) (storage KeyValueStorage, err error) {
	var schema *masterSchema
	if schema, err = extractMasterDetailSchema(rowType, tableName); err != nil {
		return
	}

	var fields = make([]SqlColumn, 0)
	fields = append(fields, schema.masterField)
	for _, f := range schema.dataFields {
		fields = append(fields, f)
	}
	var keys = []string{schema.masterField.GetColumnName()}
	if err = db.VerifyTable(schema.tableName, fields, keys, nil); err != nil {
		return
	}
	for _, detail := range schema.details {
		fields = make([]SqlColumn, 0)
		fields = append(fields, detail.masterField, detail.detailField)
		for _, f := range detail.dataFields {
			fields = append(fields, f)
		}
		keys = []string{detail.masterField.GetColumnName(), detail.detailField.GetColumnName()}
		if err = db.VerifyTable(detail.tableName, fields, keys, nil); err != nil {
			return
		}
	}

	storage = &masterDetailStorage{
		db:     db,
		schema: schema,
	}
	return
}

func extractMasterDetailSchema(masterType reflect.Type, tableName string) (schema *masterSchema, err error) {
	var extractInfo *masterExtractInfo
	if extractInfo, err = extractMasterFields(masterType); err != nil {
		return
	}
	for _, ch := range extractInfo.children {
		if len(ch.children) > 0 {
			err = errors.New("not supported")
			return
		}
	}

	if !masterType.Implements(reflect.TypeOf((*Initializer)(nil)).Elem()) {
		err = errors.New(fmt.Sprintf("%s: should implement Initializer interface", masterType.Name()))
		return
	}

	schema = &masterSchema{
		masterDetailSchema: masterDetailSchema{
			baseSchema: baseSchema{
				dataFields: nil,
				rowType:    masterType,
			},
			masterField: nil,
			queries:     make(map[QueryType]string),
		},
		details: nil,
	}
	schema.SetTableName(tableName)

	for _, f := range extractInfo.fields {
		if f.HasKey("master") {
			if schema.masterField != nil {
				err = errors.New("multiple master fields")
				return
			}
			schema.masterField = f
		} else {
			schema.dataFields = append(schema.dataFields, f)
		}
	}
	if schema.masterField == nil {
		err = errors.New("no master field defined")
		return
	}

	for _, d := range extractInfo.children {
		detailSchema := &detailSchema{
			masterDetailSchema: masterDetailSchema{
				baseSchema: baseSchema{
					tableName:  d.columnName,
					dataFields: nil,
					rowType:    d.rowType,
				},
				masterField: nil,
				queries:     make(map[QueryType]string),
			},
			detailField: nil,
			fieldIndex: d.fieldIndex,
			extraTags: d.extraTags,
		}
		detailSchema.SetTableName(tableName + "_" + d.columnName)
		for _,f := range d.fields {
			if f.HasKey("master") {
				if detailSchema.masterField != nil {
					err = errors.New("multiple master columns")
					return
				}
				detailSchema.masterField = f
			} else if f.HasKey("detail") {
				if detailSchema.detailField != nil {
					err = errors.New("multiple detail columns")
					return
				}
				detailSchema.detailField = f
			} else {
				detailSchema.dataFields = append(detailSchema.dataFields, f)
			}
		}
		if detailSchema.masterField == nil {
			err = errors.New("no master field defined")
			return
		}
		if detailSchema.detailField == nil {
			err = errors.New("no detail field defined")
			return
		}
		schema.details = append(schema.details, detailSchema)
	}
	return
}

