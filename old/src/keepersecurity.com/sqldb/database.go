package sqldb

import (
	"database/sql"
	"errors"
	"github.com/golang/glog"
	"reflect"
	"strings"
)

type stmtQueue struct {
	arr []*sql.Stmt
}

func (q *stmtQueue) Push(stmt *sql.Stmt) {
	q.arr = append(q.arr, stmt)
}
func (q *stmtQueue) Pop() (stmt *sql.Stmt, err error) {
	if len(q.arr) > 0 {
		stmt = q.arr[0]
		q.arr = q.arr[1:]
	} else {
		err = errors.New("empty queue")
	}
	return
}
func (q *stmtQueue) Len() int {
	return len(q.arr)
}

type GenericDatabase struct {
	stmtCache map[string]*stmtQueue
	db        *sql.DB
	txn       *sql.Tx
}

func NewGenericDatabase(database *sql.DB) *GenericDatabase {
	return &GenericDatabase{
		db: database,
	}
}
func (db *GenericDatabase) GetStatement(query string) (stmt *sql.Stmt, err error) {
	if db.stmtCache != nil {
		if queue, ok := db.stmtCache[query]; ok {
			stmt, _ = queue.Pop()
			if stmt != nil {
				return
			}
		}
	}
	if db.txn != nil {
		stmt, err = db.txn.Prepare(query)
	} else {
		stmt, err = db.db.Prepare(query)
	}
	return
}
func (db *GenericDatabase) ReuseStatement(query string, stmt *sql.Stmt) {
	if db.stmtCache == nil {
		db.stmtCache = make(map[string]*stmtQueue)
	}
	var queue *stmtQueue
	var ok bool
	if queue, ok = db.stmtCache[query]; !ok {
		queue = new(stmtQueue)
		db.stmtCache[query] = queue
	}
	if queue.Len() < 3 {
		queue.Push(stmt)

	} else {
		if err := stmt.Close(); err != nil {
			glog.V(2).Info("close statement", err)
		}
	}
}
func (db *GenericDatabase) ClearStatementCache() {
	cache := db.stmtCache
	db.stmtCache = nil
	if cache != nil {
		for _, v := range cache {
			if v.Len() > 0 {
				for _, stmt := range v.arr {
					if err := stmt.Close(); err != nil {
						glog.V(2).Info("close statement", err)
					}
				}
			}
		}
	}
}

func (db *GenericDatabase) Begin() (err error) {
	if db.txn == nil {
		db.ClearStatementCache()
		db.txn, err = db.db.Begin()
	} else {
		err = errors.New("already in transaction")
	}
	return
}

func (db *GenericDatabase) Commit() (err error) {
	if db.txn != nil {
		db.ClearStatementCache()
		err = db.txn.Commit()
	} else {
		err = errors.New("not in transaction")
	}
	return
}

func (db *GenericDatabase) Rollback() (err error) {
	if db.txn != nil {
		db.ClearStatementCache()
		err = db.txn.Rollback()
	} else {
		err = errors.New("not in transaction")
	}
	return
}
func (db *GenericDatabase) IsInTransaction() bool {
	return db.txn != nil
}

func GetScanner(value reflect.Value, keyFields []interface{}, dataFields []interface{}) (result []interface{}, err error) {
	result = make([]interface{}, 0)
	for _, fields := range [][]interface{}{keyFields, dataFields} {
		for _, intf := range fields {
			switch f := intf.(type) {
			case Field:
				result = append(result, value.Field(f.FieldIndex()).Addr().Interface())
			default:
				result = append(result, intf)
			}
		}
	}
	return
}
func getValuer(value reflect.Value, fields [][]interface{}) (result []interface{}, err error) {
	result = make([]interface{}, 0)
	var ok bool
	var field Field
	eValue := value.Elem()
	var fieldArr []interface{}
	for _, fieldArr = range fields {
		for _, intf := range fieldArr {
			var fieldValue interface{} = nil
			if intf != nil {
				if field, ok = intf.(Field); ok {
					var fv = eValue.Field(field.FieldIndex())
					fieldValue = fv.Interface()
				} else {
					fieldValue = intf
				}
			}
			result = append(result, fieldValue)
		}
	}
	return
}
func GetUpdateValuer(value reflect.Value, keyFields []interface{}, dataFields []interface{}) (result []interface{}, err error) {
	return getValuer(value, [][]interface{}{dataFields, keyFields})
}
func GetInsertValuer(value reflect.Value, keyFields []interface{}, dataFields []interface{}) (result []interface{}, err error) {
	return getValuer(value, [][]interface{}{keyFields, dataFields})
}

func SelectQuery(db Database, tableName string, keyColumns []string, dataColumns []string) string {
	var builder strings.Builder
	builder.WriteString("SELECT ")
	var col string
	var i int
	for i, col = range keyColumns {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(col)
	}
	for _, column := range dataColumns {
		builder.WriteString(", ")
		builder.WriteString(column)
	}
	builder.WriteString(" FROM ")
	builder.WriteString(tableName)
	builder.WriteString(" WHERE ")
	for i, column := range keyColumns {
		if i > 0 {
			builder.WriteString(" AND ")
		}
		builder.WriteString(column)
		builder.WriteString(" = ")
		builder.WriteString(db.GetParameterName(i + 1))
	}
	return builder.String()
}

func UpdateQuery(db Database, tableName string, keyColumns []string, dataColumns []string) string {
	var builder strings.Builder
	builder.WriteString("UPDATE ")
	builder.WriteString(tableName)
	builder.WriteString(" SET ")
	var col string
	var i int
	for i, col = range dataColumns {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(col)
		builder.WriteString(" = ")
		builder.WriteString(db.GetParameterName(i + 1))
	}
	builder.WriteString(" WHERE ")
	for i, col = range keyColumns {
		if i > 0 {
			builder.WriteString(" AND ")
		}
		builder.WriteString(col)
		builder.WriteString(" = ")
		builder.WriteString(db.GetParameterName(len(dataColumns) + i + 1))
	}
	return builder.String()
}

func InsertQuery(db Database, tableName string, keyColumns []string, dataColumns []string) string {
	var builder strings.Builder
	builder.WriteString("INSERT INTO ")
	builder.WriteString(tableName)
	builder.WriteString(" (")
	var col string
	var i int
	for i, col = range keyColumns {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(col)
	}
	for _, col = range dataColumns {
		builder.WriteString(", ")
		builder.WriteString(col)
	}
	builder.WriteString(") VALUES (")
	for i = 0; i < len(keyColumns); i++ {
		if i > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(db.GetParameterName(i + 1))
	}
	for i = 0; i < len(dataColumns); i++ {
		builder.WriteString(", ")
		builder.WriteString(db.GetParameterName(len(keyColumns) + i + 1))
	}
	builder.WriteString(")")
	return builder.String()
}

func DeleteQuery(db Database, tableName string, keyColumns []string) string {
	var builder strings.Builder
	builder.WriteString("DELETE FROM ")
	builder.WriteString(tableName)
	builder.WriteString(" WHERE ")
	for i, column := range keyColumns {
		if i > 0 {
			builder.WriteString(" AND ")
		}
		builder.WriteString(column)
		builder.WriteString(" = ")
		builder.WriteString(db.GetParameterName(i + 1))
	}
	return builder.String()
}
