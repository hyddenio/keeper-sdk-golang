package main

import (
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/enterprise"
	"github.com/keeper-security/keeper-sdk-golang/sdk/helpers"
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
		panic(step)
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
	var loader = enterprise.NewEnterpriseLoader(keeperAuth, nil)
	if err = loader.Load(); err != nil {
		panic(err)
	}
	//var enterpriseData = loader.EnterpriseData()
	//var teams = enterpriseData.Teams()
	//var team = &enterprise.Team{
	//	TeamUid:       nil,
	//	Name:          "GoTeam",
	//	RestrictEdit:  true,
	//	RestrictShare: true,
	//	RestrictView:  false,
	//}
	var errors []error
	err = enterprise.PutTeams(loader, nil, nil, [][]byte{api.Base64UrlDecode("ojrWg_Rqi1H-CX2bX6EMqA")}, func(_ []byte, er error) {
		errors = append(errors, er)
	})
	if err != nil {
		panic(err)
	} else {
		for _, er := range errors {
			fmt.Print(er)
		}
	}
}
