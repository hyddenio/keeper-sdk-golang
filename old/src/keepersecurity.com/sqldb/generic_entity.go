package sqldb

import (
	"database/sql"
  "errors"
  "fmt"
  "reflect"

  "github.com/golang/glog"
  "keepersecurity.com/sdk/vault"
)

type sqlEntityStorage struct {
	entityInfo EntitySchema
	tenantInfo TenantInfo
	db         Database
	queries    map[string]string
}

func createSqlEntity(db Database, entityInfo EntitySchema, tenantInfo TenantInfo) (entity *sqlEntityStorage, err error) {
	entity = &sqlEntityStorage{
		entityInfo: entityInfo,
		tenantInfo: tenantInfo,
		db:         db,
		queries:    make(map[string]string),
	}
	return
}

func (s *sqlEntityStorage) Verify() (err error) {
	var columns = make([]SqlColumn, 0)
	columns = append(columns, s.tenantInfo.TenantColumn())
	columns = append(columns, s.entityInfo.GetUidField())
	for _, f := range s.entityInfo.GetDataFields() {
		columns = append(columns, f)
	}
	return s.db.VerifyTable(s.entityInfo.GetTableName(), columns,
		[]string{s.tenantInfo.TenantColumn().GetColumnName(), s.entityInfo.GetUidField().GetColumnName()},
		nil)
}

func (s *sqlEntityStorage) Delete(uid string) {
	var ok bool
	var query string
	queryName := "delete"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName(), s.entityInfo.GetUidField().GetColumnName()}
		query = DeleteQuery(s.db, s.entityInfo.GetTableName(), keyColumns)
		glog.V(2).Infoln(queryName, query)
		s.queries[queryName] = query
	}
	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		_, err = stmt.Exec(s.tenantInfo.TenantUid(), uid)
		stmt.Close()
	}
	if err != nil {
		glog.Warning("Delete SQL entity: ", s.entityInfo.GetTableName(), ": ", err)
	}
}

func (s *sqlEntityStorage) Clear() {
	var ok bool
	var query string
	queryName := "clear"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName()}
		query = DeleteQuery(s.db, s.entityInfo.GetTableName(), keyColumns)
		glog.V(2).Infoln(queryName, query)
		s.queries[queryName] = query
	}
	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		_, err = stmt.Exec(s.tenantInfo.TenantUid())
		stmt.Close()
	}
	if err != nil {
		glog.Warning("Clear SQL entity: ", s.entityInfo.GetTableName(), ": ", err)
	}
}

func (s *sqlEntityStorage) GetEntity(uid string) (result vault.IUid) {
	var fields = s.entityInfo.GetDataFields()

	var ok bool
	var query string
	queryName := "get"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName(), s.entityInfo.GetUidField().GetColumnName()}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = SelectQuery(s.db, s.entityInfo.GetTableName(), keyColumns, dataColumns)
		s.queries[queryName] = query
	}
	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		var row = stmt.QueryRow(s.tenantInfo.TenantUid(), uid)
		value := s.entityInfo.CreateRowValue()

		var tenant string
		var keyScanner = []interface{} {&tenant, s.entityInfo.GetUidField()}
		var dataScanner = make([]interface{}, len(fields))
		for i, f := range fields {
			dataScanner[i] = f
		}
		var scanner []interface{}
		if scanner, err = GetScanner(value.Elem(), keyScanner, dataScanner); err == nil {
			if err = row.Scan(scanner...); err == nil {
				result, _ = value.Interface().(vault.IUid)
			}
		}
		s.db.ReuseStatement(query, stmt)
	}
	if err != nil {
		glog.Warning("Get SQL entity: ", s.entityInfo.GetTableName(), ": ", err)
	}
	return
}

func (s *sqlEntityStorage) PutEntity(entity vault.IUid) {
	var value reflect.Value
	var err error
	if value, err = s.entityInfo.GetRowValue(entity); err != nil {
		glog.Warning("Put SQL entity: ", s.entityInfo.GetTableName(), ": ", err)
		return
	}

	var fields = s.entityInfo.GetDataFields()

	var ok bool
	var queryName = "update"
	var query string
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName(), s.entityInfo.GetUidField().GetColumnName()}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = UpdateQuery(s.db, s.entityInfo.GetTableName(), keyColumns, dataColumns)
		s.queries[queryName] = query
	}

	var stmt *sql.Stmt
	var result sql.Result
	var keyColumns = []interface{} {s.tenantInfo.TenantUid(), entity.Uid()}
	var dataColumns = make([]interface{}, len(fields))
	for i, f := range fields {
		dataColumns[i] = f
	}
	var values []interface{}

	if stmt, err = s.db.GetStatement(query); err == nil {
		var updated = false
		if values, err = GetUpdateValuer(value, keyColumns, dataColumns); err == nil {
			if result, err = stmt.Exec(values...); err == nil {
				var affected int64
				if affected, err = result.RowsAffected(); err == nil {
					updated = affected > 0
				}
			}
		}
		s.db.ReuseStatement(query, stmt)
		if updated {
			return
		}
	}

	queryName = "insert"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName(), s.entityInfo.GetUidField().GetColumnName()}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = InsertQuery(s.db, s.entityInfo.GetTableName(), keyColumns, dataColumns)
		s.queries[queryName] = query
	}

	if stmt, err = s.db.GetStatement(query); err == nil {
		if values, err = GetInsertValuer(value, keyColumns, dataColumns); err == nil {
			if result, err = stmt.Exec(values...); err == nil {
				var affected int64
				if affected, err = result.RowsAffected(); err == nil {
					if affected == 0 {
						err = errors.New("not inserted")
					}
				}
			}
		}
		s.db.ReuseStatement(query, stmt)
	}
	if err != nil {
		glog.Warning("Put SQL entity: ", s.entityInfo.GetTableName(), ": ", err)
	}
}

func (s *sqlEntityStorage)EnumerateEntities(callback func (vault.IUid) bool) {
	var fields = append([]Field{s.entityInfo.GetUidField()}, s.entityInfo.GetDataFields()...)

	var ok bool
	var query string
	queryName := "enumerate"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName()}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = SelectQuery(s.db, s.entityInfo.GetTableName(), keyColumns, dataColumns)
		s.queries[queryName] = query
	}

	var stmt *sql.Stmt
	var err error
	var res vault.IUid
	if stmt, err = s.db.GetStatement(query); err == nil {
		var rows *sql.Rows
		if rows, err = stmt.Query(s.tenantInfo.TenantUid()); err == nil {
			var values []interface{}
			var tenantUid string
			var keyValues = []interface{}{&tenantUid}
			var dataValues = make([]interface{}, len(fields))
			for i, f := range fields {
				dataValues[i] = f
			}
			for rows.Next() {
				value := s.entityInfo.CreateRowValue()
				if values, err = GetScanner(value.Elem(), keyValues, dataValues); err == nil {
					if err = rows.Scan(values...); err == nil {
						if res, ok = value.Interface().(vault.IUid); ok {
							if !callback(res) {
								break
							}
						} else {
							var rowType = value.Elem().Type()
							err = errors.New(fmt.Sprintf("struct %s does not implement IUid interface ", rowType.Name()))
							break
						}
					} else {
						break
					}
				}
			}
			_ = rows.Close()
		}
		s.db.ReuseStatement(query, stmt)
	}
	if err != nil {
		glog.Warning("Get all SQL entities: ", s.entityInfo.GetTableName(), ": ", err)
	}
}
