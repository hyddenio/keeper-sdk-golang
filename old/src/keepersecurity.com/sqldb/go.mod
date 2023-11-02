module keepersecurity.com/sqldb

go 1.14

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/mattn/go-sqlite3 v1.14.6 // indirect
	gotest.tools v2.2.0+incompatible
	keepersecurity.com/sdk v0.0.0
)

replace keepersecurity.com/sdk v0.0.0 => ../sdk
