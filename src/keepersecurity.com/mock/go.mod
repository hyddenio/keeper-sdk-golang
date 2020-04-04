module mock

go 1.13

require (
	gotest.tools v2.2.0+incompatible
	keepersecurity.com/sdk v0.0.0-00010101000000-000000000000
	keepersecurity.com/sqlite v0.0.0-00010101000000-000000000000
)

replace keepersecurity.com/sdk => ../sdk

replace keepersecurity.com/sqlite => ../sqlite
