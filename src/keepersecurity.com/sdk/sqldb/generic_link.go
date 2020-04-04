package sqldb

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/golang/glog"
	"keepersecurity.com/sdk"
	"reflect"
)

type sqlLinkStorage struct {
	linkInfo   LinkSchema
	tenantInfo TenantInfo
	db         Database
	queries    map[string]string
}

func createSqlLink(db Database, linkInfo LinkSchema, tenantInfo TenantInfo) (entity *sqlLinkStorage, err error) {
	entity = &sqlLinkStorage{
		linkInfo:   linkInfo,
		tenantInfo: tenantInfo,
		db:         db,
		queries:    make(map[string]string),
	}
	return
}

func (s *sqlLinkStorage) Verify() (err error) {
	var columns = make([]SqlColumn, 0)
	columns = append(columns, s.tenantInfo.TenantColumn())
	columns = append(columns, s.linkInfo.GetSubjectField())
	columns = append(columns, s.linkInfo.GetObjectField())
	for _, f := range s.linkInfo.GetDataFields() {
		columns = append(columns, f)
	}

	err = s.db.VerifyTable(s.linkInfo.GetTableName(), columns,
		[]string{s.tenantInfo.TenantColumn().GetColumnName(), s.linkInfo.GetSubjectField().GetColumnName(), s.linkInfo.GetObjectField().GetColumnName()},
		[][]string{{s.tenantInfo.TenantColumn().GetColumnName(), s.linkInfo.GetObjectField().GetColumnName()}})

	return
}

func (s *sqlLinkStorage) Delete(subjectUid string, objectUid string) {
	var ok bool
	var query string
	queryName := "delete"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string {
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetSubjectField().GetColumnName(),
			s.linkInfo.GetObjectField().GetColumnName(),
		}
		query = DeleteQuery(s.db, s.linkInfo.GetTableName(), keyColumns)
		glog.V(2).Infoln(queryName, query)
		s.queries[queryName] = query
	}
	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		_, err = stmt.Exec(s.tenantInfo.TenantUid(), subjectUid, objectUid)
		stmt.Close()
	}
	if err != nil {
		glog.Warning("Delete SQL link", s.linkInfo.GetTableName(), err)
	}
}

func (s *sqlLinkStorage) DeleteSubject(subjectUid string) {
	var ok bool
	var query string
	queryName := "delete_subject"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetSubjectField().GetColumnName(),
		}
		query = DeleteQuery(s.db, s.linkInfo.GetTableName(), keyColumns)
		glog.V(2).Infoln(queryName, query)
		s.queries[queryName] = query
	}
	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		_, err = stmt.Exec(s.tenantInfo.TenantUid(), subjectUid)
		stmt.Close()
	}
	if err != nil {
		glog.Warning("Delete SQL link subject", s.linkInfo.GetTableName(), err)
	}
}

func (s *sqlLinkStorage) DeleteObject(objectUid string) {
	var ok bool
	var query string
	queryName := "delete_object"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetObjectField().GetColumnName(),
		}
		query = DeleteQuery(s.db, s.linkInfo.GetTableName(), keyColumns)
		glog.V(2).Infoln(queryName, query)
		s.queries[queryName] = query
	}
	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		_, err = stmt.Exec(s.tenantInfo.TenantUid(), objectUid)
		stmt.Close()
	}
	if err != nil {
		glog.Warning("Delete SQL link object", s.linkInfo.GetTableName(), err)
	}
}

func (s *sqlLinkStorage) Clear() {
	var ok bool
	var query string
	queryName := "clear"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
		}
		query = DeleteQuery(s.db, s.linkInfo.GetTableName(), keyColumns)
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
		glog.Warning("Clear SQL entity", s.linkInfo.GetTableName(), err)
	}
}

func (s *sqlLinkStorage) PutLink(link sdk.IUidLink) {
	var value reflect.Value
	var err error
	if value, err = s.linkInfo.GetRowValue(link); err != nil {
		glog.Warning("Put SQL link", s.linkInfo.GetTableName(), err)
		return
	}

	fields := s.linkInfo.GetDataFields()

	var ok bool
	var stmt *sql.Stmt
	var values []interface{}
	var keyValues = []interface{}{s.tenantInfo.TenantUid(), link.SubjectUid(), link.ObjectUid()}
	var dataValues = make([]interface{}, len(fields))
	for i, f := range fields {
		dataValues[i] = f
	}

	var query string
	var queryName string
	if len(fields) > 0 {
		queryName = "update"
		if query, ok = s.queries[queryName]; !ok {
			var keyColumns = []string{
				s.tenantInfo.TenantColumn().GetColumnName(),
				s.linkInfo.GetSubjectField().GetColumnName(),
				s.linkInfo.GetObjectField().GetColumnName(),
			}
			var dataColumns = make([]string, len(fields))
			for i, f := range fields {
				dataColumns[i] = f.GetColumnName()
			}
			query = UpdateQuery(s.db, s.linkInfo.GetTableName(), keyColumns, dataColumns)
			s.queries[queryName] = query
		}

		if stmt, err = s.db.GetStatement(query); err == nil {
			var updated = false
			if values, err = GetUpdateValuer(value, keyValues, dataValues); err == nil {
				var result sql.Result
				if result, err = stmt.Exec(values...); err == nil {
					var affected int64
					if affected, err = result.RowsAffected(); err == nil {
						updated = affected > 0
					}
				} else {
					err = nil
				}
			}
			s.db.ReuseStatement(query, stmt)
			if updated {
				return
			}
		}
	}
	if err != nil {
		glog.Warning("Update SQL link", s.linkInfo.GetTableName(), err)
	}

	queryName = "insert"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetSubjectField().GetColumnName(),
			s.linkInfo.GetObjectField().GetColumnName(),
		}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = InsertQuery(s.db, s.linkInfo.GetTableName(), keyColumns, dataColumns)
		s.queries[queryName] = query
	}

	if stmt, err = s.db.GetStatement(query); err == nil {
		if values, err = GetInsertValuer(value, keyValues, dataValues); err == nil {
			var result sql.Result
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
		glog.Warning("Insert SQL link", s.linkInfo.GetTableName(), err)
	}
}

func (s *sqlLinkStorage) GetLink(subjectUid string, objectUid string) (result sdk.IUidLink) {
	fields := s.linkInfo.GetDataFields()

	var ok bool
	var query string
	queryName := "get"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetSubjectField().GetColumnName(),
			s.linkInfo.GetObjectField().GetColumnName(),
		}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = SelectQuery(s.db, s.linkInfo.GetTableName(), keyColumns, dataColumns)
		glog.V(2).Info(queryName, query)
		s.queries[queryName] = query
	}

	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		var row = stmt.QueryRow(s.tenantInfo.TenantUid(), subjectUid, objectUid)
		value := s.linkInfo.CreateRowValue()
		var tenantUid string
		var keyValues = []interface{}{&tenantUid, s.linkInfo.GetSubjectField(), s.linkInfo.GetObjectField()}
		var dataValues = make([]interface{}, len(fields))
		for i, f := range fields {
			dataValues[i] = f
		}
		var values []interface{}
		if values, err = GetScanner(value.Elem(), keyValues, dataValues); err == nil {
			if err = row.Scan(values...); err == nil {
				if result, ok = value.Interface().(sdk.IUidLink); !ok {
					var t = value.Elem().Type()
					err = errors.New(fmt.Sprintf("type %s does not implement IUidLink", t.Name()))
				}
			}
		}
		s.db.ReuseStatement(query, stmt)
	}
	if err != nil {
		glog.Warning("Get SQL link", s.linkInfo.GetTableName(), err)
	}
	return
}

func (s *sqlLinkStorage) GetLinksForSubject(subjectUid string, callback func (sdk.IUidLink) bool) {
	fields := append([]Field{s.linkInfo.GetObjectField()},  s.linkInfo.GetDataFields()...)

	var ok bool
	var query string
	queryName := "get_subject"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetSubjectField().GetColumnName(),
		}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = SelectQuery(s.db, s.linkInfo.GetTableName(), keyColumns, dataColumns)
		glog.V(2).Info(queryName, query)
		s.queries[queryName] = query
	}

	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		var tenantUid string
		var keyValues = []interface{}{&tenantUid, s.linkInfo.GetSubjectField()}
		var dataValues = make([]interface{}, len(fields))
		for i, f := range fields {
			dataValues[i] = f
		}
		var values []interface{}

		var rows *sql.Rows
		if rows, err = stmt.Query(s.tenantInfo.TenantUid(), subjectUid); err == nil {
			for rows.Next() {
				value := s.linkInfo.CreateRowValue()
				if values, err = GetScanner(value.Elem(), keyValues, dataValues); err == nil {
					if err = rows.Scan(values...); err == nil {
						var link sdk.IUidLink
						if link, ok = value.Interface().(sdk.IUidLink); ok {
							if !callback(link) {
								break
							}
						} else {
							var t = value.Elem().Type()
							err = errors.New(fmt.Sprintf("type %s does not implement IUidLink", t.Name()))
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
		glog.Warning("Get SQL links for subject: ", s.linkInfo.GetTableName(), ": ", err)
	}
}

func (s *sqlLinkStorage) GetLinksForObject(objectUid string, callback func (sdk.IUidLink) bool) {
	fields := append([]Field{s.linkInfo.GetSubjectField()},  s.linkInfo.GetDataFields()...)

	var ok bool
	var query string
	queryName := "get_object"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{
			s.tenantInfo.TenantColumn().GetColumnName(),
			s.linkInfo.GetObjectField().GetColumnName(),
		}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = SelectQuery(s.db, s.linkInfo.GetTableName(), keyColumns, dataColumns)
		glog.V(2).Info(queryName, query)
		s.queries[queryName] = query
	}

	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		var tenantUid string
		var keyValues = []interface{}{&tenantUid, s.linkInfo.GetObjectField()}
		var dataValues = make([]interface{}, len(fields))
		for i, f := range fields {
			dataValues[i] = f
		}
		var values []interface{}

		var rows *sql.Rows
		if rows, err = stmt.Query(s.tenantInfo.TenantUid(), objectUid); err == nil {
			for rows.Next() {
				value := s.linkInfo.CreateRowValue()
				if values, err = GetScanner(value.Elem(), keyValues, dataValues); err == nil {
					if err = rows.Scan(values...); err == nil {
						var link sdk.IUidLink
						if link, ok = value.Interface().(sdk.IUidLink); ok {
							if !callback(link) {
								break
							}
						} else {
							var t = value.Elem().Type()
							err = errors.New(fmt.Sprintf("type %s does not implement IUidLink", t.Name()))
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
		glog.Warning("Get SQL links for object", s.linkInfo.GetTableName(), err)
	}
}

func (s *sqlLinkStorage) GetAllLinks(callback func (sdk.IUidLink) bool) {
	fields := append([]Field{s.linkInfo.GetSubjectField(), s.linkInfo.GetObjectField()}, s.linkInfo.GetDataFields()...)

	var ok bool
	var query string
	queryName := "get_all"
	if query, ok = s.queries[queryName]; !ok {
		var keyColumns = []string{s.tenantInfo.TenantColumn().GetColumnName()}
		var dataColumns = make([]string, len(fields))
		for i, f := range fields {
			dataColumns[i] = f.GetColumnName()
		}
		query = SelectQuery(s.db, s.linkInfo.GetTableName(), keyColumns, dataColumns)
		glog.V(2).Info(queryName, query)
		s.queries[queryName] = query
	}

	var stmt *sql.Stmt
	var err error
	if stmt, err = s.db.GetStatement(query); err == nil {
		if rows, err := stmt.Query(s.tenantInfo.TenantUid()); err == nil {
			var tenantUid string
			var keyValues = []interface{}{&tenantUid}
			var dataValues = make([]interface{}, len(fields))
			for i, f := range fields {
				dataValues[i] = f
			}
			var values []interface{}

			for rows.Next() {
				value := s.linkInfo.CreateRowValue()
				if values, err = GetScanner(value.Elem(), keyValues, dataValues); err == nil {
					if err = rows.Scan(values...); err == nil {
						var link sdk.IUidLink
						if link, ok = value.Interface().(sdk.IUidLink); ok {
							if !callback(link) {
								break
							}
						} else {
							var t = value.Elem().Type()
							err = errors.New(fmt.Sprintf("type %s does not implement IUidLink", t.Name()))
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
		glog.Warning("Get all SQL links", s.linkInfo.GetTableName(), err)
	}
}
