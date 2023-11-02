package sqlite

import (
	"database/sql"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"keepersecurity.com/sdk/vault"
	"keepersecurity.com/sqldb"
)

type sqliteDatabase struct {
	*sqldb.GenericDatabase
	filename string
}

type sqliteColumn struct {
	name string
	dataType string
	isNotNull bool
	isPk int
}
func (db *sqliteDatabase) VerifyTable(
	tableName string, columns []sqldb.SqlColumn,
	primaryKey []string, indexes [][]string) (err error) {

	var dbColumns = make(map[string]*sqliteColumn)
	query := "PRAGMA table_info('" + tableName + "')"
	var stmt *sql.Stmt
	if stmt, err = db.GetStatement(query); err == nil {
		var rows *sql.Rows
		if rows, err = stmt.Query(); err == nil {
			for rows.Next() {
				var column = new(sqliteColumn)
				var no int
				var def sql.NullString
				if err = rows.Scan(&no, &(column.name), &(column.dataType), &(column.isNotNull), &def, &(column.isPk)); err == nil {
					dbColumns[strings.ToLower(column.name)] = column
				} else {
					break
				}
			}
			_ = rows.Close()
		}
		_ = stmt.Close()
	}
	if err != nil {
		return
	}

	if len(dbColumns) == 0 {      // create table
		var keyColumns vault.Set
		for _, col := range primaryKey {
			keyColumns.Add(col)
		}
		for _, index := range indexes {
			for _, col := range index {
				keyColumns.Add(col)
			}
		}
		var builder strings.Builder
		builder.WriteString("CREATE TABLE ")
		builder.WriteString(tableName)
		builder.WriteString(" (")
		for _, c := range columns {
			builder.WriteString("\n\t")
			builder.WriteString(c.GetColumnName())
			builder.WriteString(" ")
			switch c.SqlType() {
			case sqldb.String:
				builder.WriteString("TEXT")
			case sqldb.Integer, sqldb.Bool:
				builder.WriteString("INTEGER")
			case sqldb.Numeric:
				builder.WriteString("REAL")
			case sqldb.Blob:
				builder.WriteString("BLOB")
			default:
				builder.WriteString("TEXT")
			}
			if keyColumns.IsSet(c.GetColumnName()) {
				builder.WriteString(" NOT NULL")
			}
			builder.WriteString(",")
		}
		builder.WriteString("\n\n\tPRIMARY KEY (")
		for i, k := range primaryKey {
			if i > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(k)
		}
		builder.WriteString(")")
		builder.WriteString("\n)")

		query = builder.String()
		if stmt, err = db.GetStatement(query); err == nil {
			_, err = stmt.Exec()
			_ = stmt.Close()
		}
		if err != nil {
			return
		}
	} else {
		for _, c := range columns {
			var ok bool
			if _, ok = dbColumns[strings.ToLower(c.GetColumnName())]; !ok {
				var builder strings.Builder
				builder.WriteString("CREATE TABLE ")
				builder.WriteString(tableName)
				builder.WriteString(" ADD COLUMN ")
				builder.WriteString(c.GetColumnName())
				builder.WriteString(" ")
				switch c.SqlType() {
				case sqldb.String:
					builder.WriteString("TEXT")
				case sqldb.Integer, sqldb.Bool:
					builder.WriteString("INTEGER")
				case sqldb.Numeric:
					builder.WriteString("REAL")
				case sqldb.Blob:
					builder.WriteString("BLOB")
				default:
					builder.WriteString("TEXT")
				}
				query = builder.String()
				if stmt, err = db.GetStatement(query); err == nil {
					_, err = stmt.Exec()
					_ = stmt.Close()
				}
				if err != nil {
					return
				}
			}
		}
	}

	if len(indexes) > 0 {
		var indice = make([]string,0)
		query = "PRAGMA index_list('" + tableName + "')"
		if stmt, err = db.GetStatement(query); err == nil {
			var rows *sql.Rows
			if rows, err = stmt.Query(); err == nil {
				for rows.Next() {
					var no int
					var indexName string
					var isUnique bool
					var isPartial bool
					var indexType string
					if err = rows.Scan(&no, &indexName, &isUnique, &indexType, &isPartial); err == nil {
						if !isPartial && indexType == "c" {
							indice = append(indice, indexName)
						}
					} else {
						break
					}
				}
				_ = rows.Close()
			}
			_ = stmt.Close()
		}
		if err != nil {
			return
		}
		var indexColumns = make([][]string, 0)
		for _, indexName := range indice {
			var cols = make(map[int]string)
			query = "PRAGMA index_info('" + indexName + "')"
			if stmt, err = db.GetStatement(query); err == nil {
				var rows *sql.Rows
				if rows, err = stmt.Query(); err == nil {
					for rows.Next() {
						var rank int
						var columnRank int
						var columnName string
						if err = rows.Scan(&rank, &columnRank, &columnName); err == nil {
							if columnRank < 0 || columnName == "" {
								break
							}
							cols[rank] = columnName
						} else {
							break
						}

					}
					_ = rows.Close()

				}
				_ = stmt.Close()
			}
			if len(cols) > 0 {
				var ok = true
				var colNames = make([]string, len(cols))
				for idx, name := range(cols) {
					if idx >= 0 && idx < len(colNames) {
						colNames[idx] = name
					} else {
						ok = false
						break
					}
				}
				if ok {
					indexColumns = append(indexColumns, colNames)
				}
			}
		}
		for _, checkIdx := range indexes {
			var found = false
			for _, existingIdx := range indexColumns {
				if len(existingIdx) >= len(checkIdx) {
					found = true
					for i := 0; i < len(checkIdx); i++ {
						if strings.ToLower(checkIdx[i]) != strings.ToLower(existingIdx[i]) {
							found = false
							break
						}
					}
					if found {
						break
					}
				}
			}
			if !found {
				var builder strings.Builder
				builder.WriteString("CREATE INDEX ")
				builder.WriteString(tableName)
				for _, sc := range checkIdx {
					builder.WriteString("_")
					builder.WriteString(sc)
				}
				builder.WriteString("_idx ON ")
				builder.WriteString(tableName)
				builder.WriteString(" (")
				for i, sc := range checkIdx {
					if i > 0 {
						builder.WriteString(", ")
					}
					builder.WriteString(sc)
				}
				builder.WriteString(")")

				query = builder.String()
				if stmt, err = db.GetStatement(query); err == nil {
					_, err = stmt.Exec()
					_ = stmt.Close()
				}
				if err != nil {
					return
				}
			}
		}
	}
	return
}

func (db *sqliteDatabase) GetParameterName(_ int) string {
	return "?"
}

func OpenSqliteDatabase(filename string) (database sqldb.Database, err error) {
	var db *sql.DB
	if db, err = sql.Open("sqlite3", filename); err != nil {
		return
	}
	database = &sqliteDatabase{
		GenericDatabase: sqldb.NewGenericDatabase(db),
		filename: filename,
	}

	return
}

