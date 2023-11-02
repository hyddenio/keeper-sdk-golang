package sqldb

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"keepersecurity.com/sdk/vault"
)

type DataType uint32

const (
	Bool    = iota
	Integer = iota
	Numeric
	String
	Blob
)

type column struct {
	sqlName    string
	sqlType    DataType
	precision  int
	fieldIndex int
	extraTags  vault.Set
}

func (f *column) GetColumnName() string {
	return f.sqlName
}
func (f *column) SqlType() DataType {
	return f.sqlType
}
func (f *column) Precision() int {
	return f.precision
}
func (f *column) FieldIndex() int {
	return f.fieldIndex
}
func (f *column) SetColumnName(name string) {
	f.sqlName = name
}
func (f *column) HasKey(key string) bool {
	return f.extraTags.IsSet(key)
}
func (f *column) SetPrecision(value int) {
	f.precision = value
}

type baseSchema struct {
	tableName  string
	dataFields []Field
	rowType    reflect.Type
}

func (bs *baseSchema) CreateRowValue() reflect.Value {
	return reflect.New(bs.rowType.Elem())
}
func (bs *baseSchema) GetRowValue(source interface{}) (result reflect.Value, err error) {
	if source != nil && reflect.TypeOf(source) == bs.rowType {
		result = reflect.ValueOf(source)
	} else {
		result = bs.CreateRowValue()
		if source != nil {
			var initializer Initializer
			var ok bool
			if initializer, ok = result.Interface().(Initializer); ok {
				err = initializer.Init(source)
			}
		}
	}
	return
}
func (bs *baseSchema) GetDataFields() []Field {
	return bs.dataFields
}
func (bs *baseSchema) GetTableName() string {
	return bs.tableName
}
func (bs *baseSchema) SetTableName(tableName string) {
	bs.tableName = tableName
}

func getSqlDataType(t reflect.Type) (sqlDataType DataType, precision int, err error) {
	switch t.Kind() {
	case reflect.Bool:
		sqlDataType = Bool
	case reflect.Uint8, reflect.Int8:
		sqlDataType = Integer
		precision = 1
	case reflect.Uint16, reflect.Int16:
		sqlDataType = Integer
		precision = 2
	case reflect.Int32, reflect.Uint32:
		sqlDataType = Integer
		precision = 4
	case reflect.Int, reflect.Uint,
		reflect.Int64, reflect.Uint64:
		sqlDataType = Integer
		precision = 8
	case reflect.Float32:
		sqlDataType = Numeric
		precision = 4
	case reflect.Float64:
		sqlDataType = Numeric
		precision = 8
	case reflect.String:
		sqlDataType = String
	case reflect.Slice:
		{
			if t.Elem().Kind() == reflect.Uint8 {
				sqlDataType = Blob
			} else {
				err = errors.New(fmt.Sprintf("field %s: only []byte are supported", t.Name()))
				return
			}
		}
	case reflect.Struct:
		{
			switch t {
			case sqlNullInt64Type:
				sqlDataType = Integer
				precision = 8
			case sqlNullInt32Type:
				sqlDataType = Integer
				precision = 4
			case sqlNullStringType:
				sqlDataType = String
			case sqlNullBoolType:
				sqlDataType = Bool
			case sqlNullFloatType:
				sqlDataType = Numeric
				precision = 8
			default:
				err = errors.New(fmt.Sprintf("field %s: unsupported type", t.Name()))
			}
		}
	default:
		err = errors.New(fmt.Sprintf("field %s: unsupported type", t.Name()))
	}

	return
}

type MasterExtractInfo interface {
	Fields() []Field
	Children(func(DetailExtractInfo) bool)
}
type DetailExtractInfo interface {
	MasterExtractInfo
	ColumnName() string
	FieldIndex() int
	HasKey(string) bool
	RowType() reflect.Type
}

type masterExtractInfo struct {
	fields   []Field
	children []*detailExtractInfo
}

func (m *masterExtractInfo) Fields() []Field {
	return m.fields
}
func (m *masterExtractInfo) Children(callback func(DetailExtractInfo) bool) {
	for _, d := range m.children {
		if !callback(d) {
			break
		}
	}
}

type detailExtractInfo struct {
	*masterExtractInfo
	columnName string
	fieldIndex int
	rowType    reflect.Type
	extraTags  vault.Set
}

func (d *detailExtractInfo) ColumnName() string {
	return d.columnName
}
func (d *detailExtractInfo) FieldIndex() int {
	return d.fieldIndex
}
func (d *detailExtractInfo) RowType() reflect.Type {
	return d.rowType
}
func (d *detailExtractInfo) HasKey(key string) bool {
	return d.extraTags.IsSet(key)
}

func ExtractFields(entityType reflect.Type) (extractInfo MasterExtractInfo, err error) {
	return extractMasterFields(entityType)
}

func extractMasterFields(entityType reflect.Type) (extractInfo *masterExtractInfo, err error) {
	if entityType.Kind() != reflect.Ptr {
		err = errors.New(fmt.Sprintf("%s: pointer to struct expected", entityType.Name()))
		return
	}
	if entityType.Elem().Kind() != reflect.Struct {
		err = errors.New(fmt.Sprintf("%s: pointer to struct expected", entityType.Name()))
		return
	}
	entityType = entityType.Elem()

	extractInfo = new(masterExtractInfo)
	for i := 0; i < entityType.NumField(); i++ {
		field := entityType.Field(i)
		tag := field.Tag.Get("sdk")
		if tag != "" {
			props := strings.Split(tag, ",")
			var sqlName string
			var precision = 0
			var extra vault.Set
			for i, p := range props {
				if i == 0 {
					sqlName = p
				} else {
					if p != "" {
						var digitsOnly = true
						for _, ch := range p {
							if !unicode.IsDigit(ch) {
								digitsOnly = false
								break
							}
						}
						if digitsOnly {
							precision, _ = strconv.Atoi(p)
						} else {
							extra.Add(p)
						}
					}
				}
			}
			if sqlName == "" {
				continue
			}
			var dataType DataType
			var typePrecision int
			if dataType, typePrecision, err = getSqlDataType(field.Type); err == nil {
				if precision == 0 && typePrecision > 0 {
					precision = typePrecision
				}
				extractInfo.fields = append(extractInfo.fields, &column{
					sqlName:    sqlName,
					sqlType:    dataType,
					precision:  precision,
					fieldIndex: i,
					extraTags:  extra,
				})
			} else {
				if field.Type.Kind() == reflect.Slice {
					var subType = field.Type.Elem()
					var cInfo *masterExtractInfo
					if cInfo, err = extractMasterFields(subType); err == nil {
						var dInfo = &detailExtractInfo{
							masterExtractInfo: cInfo,
							columnName:        sqlName,
							fieldIndex:        i,
							rowType:           subType,
							extraTags:         extra,
						}
						extractInfo.children = append(extractInfo.children, dInfo)
					}
				}
				if err != nil {
					break
				}
			}
		}
	}
	return
}

var sqlNullInt64Type = reflect.TypeOf((*sql.NullInt64)(nil)).Elem()
var sqlNullInt32Type = reflect.TypeOf((*sql.NullInt32)(nil)).Elem()
var sqlNullStringType = reflect.TypeOf((*sql.NullString)(nil)).Elem()
var sqlNullBoolType = reflect.TypeOf((*sql.NullBool)(nil)).Elem()
var sqlNullFloatType = reflect.TypeOf((*sql.NullFloat64)(nil)).Elem()
