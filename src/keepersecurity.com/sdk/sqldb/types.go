package sqldb

import (
	"database/sql"
	"keepersecurity.com/sdk"
	"reflect"
)

type DataType uint32
const (
	Bool DataType = iota
	Integer
	Numeric
	String
	Blob
)

type SqlColumn interface {
	GetColumnName() string
	SqlType() DataType
	Precision() int
}
type Field interface {
	SqlColumn
	FieldIndex() int
	HasKey(string) bool
	SetPrecision(value int)
}

type Schema interface {
	GetTableName() string
	SetTableName(string)
	GetRowValue(interface{}) (reflect.Value, error)
	CreateRowValue() reflect.Value
	GetDataFields() []Field
}

type EntitySchema interface {
	Schema
	GetUidField() Field
}

type LinkSchema interface {
	Schema
	GetSubjectField() Field
	GetObjectField() Field
}

type Database interface {
	sdk.ITransaction
	GetStatement(string ) (*sql.Stmt, error)
	ReuseStatement(string, *sql.Stmt)
	ClearStatementCache()
	GetParameterName(int) string
	VerifyTable(string, []SqlColumn, []string, [][]string) error
}

type Initializer interface {
	Init(interface{}) error
}

