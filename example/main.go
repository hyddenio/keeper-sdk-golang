package main

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/enterprise"
	"github.com/keeper-security/keeper-sdk-golang/sdk/helpers"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	//var configStorage = helpers.NewCommanderConfiguration("")
	var configStorage = helpers.NewJsonConfigurationFile("")
	var err error
	var config auth.IKeeperConfiguration
	if config, err = configStorage.Get(); err != nil {
		panic(err)
	}

	var endpoint = helpers.NewKeeperEndpoint(config.LastServer(), configStorage)
	var loginAuth = helpers.NewLoginAuth(endpoint)
	loginAuth.Login(config.LastLogin())
	var step = loginAuth.Step()
	if step.LoginState() != auth.LoginState_Connected {
		panic(fmt.Sprintf("Invalid login state: %v", step.LoginState()))
	}
	var ok bool
	var connectedStep auth.IConnectedStep
	if connectedStep, ok = step.(auth.IConnectedStep); !ok {
		panic(step)
	}
	var keeperAuth auth.IKeeperAuth
	if keeperAuth, err = connectedStep.TakeKeeperAuth(); err != nil {
		panic(err)
	}

	var connectionString = "file::memory:?cache=shared&mode=memory"
	//var connectionString = "file:///Users/skolupaev/.keeper/keeper_db.sqlite?cache=shared&mode=rwc"
	var db *sqlx.DB
	db, err = sqlx.Connect("sqlite3", connectionString)
	if err != nil {
		panic(err)
	}

	var storage enterprise.IEnterpriseStorage
	storage, err = enterprise.NewSqliteEnterpriseStorage(func() *sqlx.DB { return db }, int64(keeperAuth.AuthContext().License().EnterpriseId))
	var loader = enterprise.NewEnterpriseLoader(keeperAuth, storage)
	if err = loader.Load(); err != nil {
		panic(err)
	}
	//var enterpriseData = loader.EnterpriseData()
	//var teams = enterpriseData.Teams()
	//var team enterprise.ITeam
	//teams.GetAllEntities(func(t enterprise.ITeam) bool {
	//	if strings.ToUpper(t.Name()) == "VAULT" {
	//		team = t
	//		return false
	//	}
	//	return true
	//})
	//if team == nil {
	//	panic("team not found")
	//}

	var te = enterprise.NewTeam(api.Base64UrlEncode(api.GenerateUid()))
	te.SetName("NNNNN")
	te.SetRestrictShare(true)

	var errors []error
	var entManager = enterprise.NewSyncEnterpriseManagement(loader)
	errors = entManager.ModifyTeams([]enterprise.ITeam{te}, nil, nil)
	//err = enterprise.PutTeams(loader, nil, nil, [][]byte{api.Base64UrlDecode("ojrWg_Rqi1H-CX2bX6EMqA")}, func(_ []byte, er error) {
	//	errors = append(errors, er)
	//})
	if err != nil {
		panic(err)
	} else {
		for _, er := range errors {
			fmt.Print(er)
		}
	}
}
