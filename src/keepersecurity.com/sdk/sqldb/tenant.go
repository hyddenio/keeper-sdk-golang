package sqldb

import (
	"database/sql"
	"errors"
	"fmt"
	"keepersecurity.com/sdk"
	"strings"
)

type baseSqlColumn struct {
	columnName string
	sqlType    DataType
	precision  int
}

func (c *baseSqlColumn) GetColumnName() string {
	return c.columnName
}
func (c *baseSqlColumn) SqlType() DataType {
	return c.sqlType
}
func (c *baseSqlColumn) Precision() int {
	return c.precision
}

type tenantSchema struct {
	tableName      string
	uidColumn      SqlColumn
	uniqueColumn   SqlColumn
	revisionColumn SqlColumn
}

type TenantInfo interface {
	TenantColumn() SqlColumn
	TenantUid() string
}
type tenantStorage struct {
	db           Database
	tenantSchema *tenantSchema
	tenantUid    string
	username     string
	env          string
	_getQuery    string
	_setQuery    string
}
func (t *tenantStorage) TenantColumn() SqlColumn {
	return t.tenantSchema.uidColumn
}
func (t *tenantStorage) TenantUid() string {
	return t.tenantUid
}
func (t *tenantStorage) Username() string {
	return t.username
}
func (t *tenantStorage) Env() string {
	return t.env
}
func (t *tenantStorage) getValue(column SqlColumn, receiver interface{}) (err error) {
	if t._getQuery == "" {
		var builder strings.Builder
		builder.WriteString("SELECT %s FROM ")
		builder.WriteString(t.tenantSchema.tableName)
		builder.WriteString(" WHERE ")
		builder.WriteString(t.tenantSchema.uidColumn.GetColumnName())
		builder.WriteString(" = ")
		builder.WriteString(t.db.GetParameterName(1))
		t._getQuery = builder.String()
	}
	var query = fmt.Sprintf(t._getQuery, column.GetColumnName())
	var stmt *sql.Stmt
	if stmt, err = t.db.GetStatement(query); err == nil {
		defer stmt.Close()
		var row = stmt.QueryRow(t.tenantUid)
		err = row.Scan(receiver)
	}
	return
}
func (t *tenantStorage) setValue(column SqlColumn, value interface{}) (err error) {
	if t._setQuery == "" {
		var builder strings.Builder
		builder.WriteString("UPDATE ")
		builder.WriteString(t.tenantSchema.tableName)
		builder.WriteString(" SET %s = ")
		builder.WriteString(t.db.GetParameterName(1))
		builder.WriteString(" WHERE ")
		builder.WriteString(t.tenantSchema.uidColumn.GetColumnName())
		builder.WriteString(" = ")
		builder.WriteString(t.db.GetParameterName(2))
		t._setQuery = builder.String()
	}
	var query = fmt.Sprintf(t._setQuery, column.GetColumnName())
	var stmt *sql.Stmt
	if stmt, err = t.db.GetStatement(query); err == nil {
		defer stmt.Close()
		var result sql.Result
		if result, err = stmt.Exec(value, t.tenantUid); err == nil {
			var affected int64
			if affected, err = result.RowsAffected(); err == nil {
				if affected == 0 {
					err = errors.New("tenant value is not stored")
				}
			}
		}
	}
	return
}

func newTenantSchema() (schema *tenantSchema, err error) {
	schema = &tenantSchema{
		tableName: "tenant",
		uidColumn: &baseSqlColumn{
			columnName: "tenant_uid",
			sqlType:    String,
			precision:  64,
		},
		uniqueColumn: &baseSqlColumn{
			columnName: "user_id",
			sqlType:    String,
			precision:  64,
		},
		revisionColumn: &baseSqlColumn{
			columnName: "revision",
			sqlType:    Integer,
			precision:  8,
		},
	}
	return
}

func newTenantStorageForEnvironment(db Database, username string, environment string) (storage *tenantStorage, err error) {
	var tenantSchema *tenantSchema
	if tenantSchema, err = newTenantSchema(); err == nil {
		err = db.VerifyTable(
			tenantSchema.tableName,
			[]SqlColumn{tenantSchema.uidColumn, tenantSchema.uniqueColumn, tenantSchema.revisionColumn},
			[]string{tenantSchema.uidColumn.GetColumnName()},
			[][]string{{tenantSchema.uniqueColumn.GetColumnName()}})
	}
	if err != nil {
		return
	}

	var tenantUid string
	var userKey = fmt.Sprintf("[%s]%s", strings.ToUpper(environment), strings.ToLower(username))
	query :=
		"SELECT " + tenantSchema.uidColumn.GetColumnName() +
			" FROM " + tenantSchema.tableName +
			" WHERE " + tenantSchema.uniqueColumn.GetColumnName() + " = " + db.GetParameterName(1)
	var stmt *sql.Stmt
	if stmt, err = db.GetStatement(query); err == nil {
		row := stmt.QueryRow(userKey)
		err = row.Scan(&tenantUid)
		_ = stmt.Close()
		if err != nil {
			tenantUid = sdk.GenerateUid()
			query = "INSERT INTO " + tenantSchema.tableName + " (" +
				tenantSchema.uidColumn.GetColumnName() + ", " +
				tenantSchema.uniqueColumn.GetColumnName() + ") VALUES (" +
				db.GetParameterName(1) + ", " + db.GetParameterName(2) + ")"
			if stmt, err = db.GetStatement(query); err == nil {
				var result sql.Result
				result, err = stmt.Exec(tenantUid, userKey)
				_ = stmt.Close()
				if err == nil {
					var inserted int64
					if inserted, err = result.RowsAffected(); err == nil {
						if inserted != 1 {
							err = errors.New("could not create tenant entry")
						}
					}
				}
			}
		}
	}

	if err == nil {
		storage = &tenantStorage{
			db:           db,
			tenantSchema: tenantSchema,
			tenantUid:    tenantUid,
			username:     username,
			env:          environment,
		}
	}
	return
}

func newTenantStorage(db Database, username string) (*tenantStorage, error) {
	return newTenantStorageForEnvironment(db, username, "PROD")
}
