package sqldb

import (
	"database/sql"
	"reflect"

	"keepersecurity.com/sdk/vault"
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
	vault.ITransaction
	GetStatement(string) (*sql.Stmt, error)
	ReuseStatement(string, *sql.Stmt)
	ClearStatementCache()
	GetParameterName(int) string
	VerifyTable(string, []SqlColumn, []string, [][]string) error
}

type Initializer interface {
	Init(interface{}) error
}
