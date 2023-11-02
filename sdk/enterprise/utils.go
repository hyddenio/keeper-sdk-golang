package enterprise

import (
	"crypto/rsa"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/json_commands"
	"go.uber.org/zap"
)

func GetEnterpriseIds(loader IEnterpriseLoader, numberRequested int) (eids []int64, err error) {
	if numberRequested <= 0 || numberRequested > 1000 {
		err = api.NewKeeperError("number of requested IDs should be positive and cannot exceed 1000")
		return
	}
	if loader.Storage() != nil {
		// TODO use storage for cached IDs
	}
	var cmd = &json_commands.EnterpriseAllocateIdsCommand{
		NumberRequested: numberRequested,
	}
	var rs = new(json_commands.EnterpriseAllocateIdsResponse)
	if err = loader.KeeperAuth().ExecuteAuthCommand(cmd, rs, true); err == nil {
		for i := 0; i < rs.NumberAllocated; i++ {
			eids = append(eids, rs.BaseId+int64(i))
		}
	}
	return
}

func PutTeams(loader IEnterpriseLoader, teamsToAdd []*Team, teamsToUpdate []*Team, teamsToDelete [][]byte,
	onError func([]byte, error)) (err error) {
	var logger = api.GetLogger()
	var requests []auth.IKeeperCommand
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var er1 error
	for _, x := range teamsToAdd {
		if len(x.TeamUid) == 0 {
			x.TeamUid = api.GenerateUid()
		}
		var t = json_commands.EnterpriseTeam{
			TeamUid:       api.Base64UrlEncode(x.TeamUid),
			TeamName:      x.Name,
			RestrictShare: x.RestrictShare,
			RestrictEdit:  x.RestrictEdit,
			RestrictView:  x.RestrictView,
		}
		t.NodeId = new(int64)
		if x.NodeId > 0 {
			*t.NodeId = x.NodeId
		} else {
			for _, n := range loader.EnterpriseData().Nodes().GetData() {
				if n.ParentId == 0 {
					*t.NodeId = n.NodeId
					break
				}
			}
		}
		var r = &json_commands.EnterpriseTeamAddCommand{
			EnterpriseTeam: t,
		}

		var teamKey = api.GenerateAesKey()
		var privKey *rsa.PrivateKey
		var pubKey *rsa.PublicKey
		if privKey, pubKey, er1 = api.GenerateRsaKey(); er1 == nil {
			r.PublicKey = api.Base64UrlEncode(api.UnloadRsaPublicKey(pubKey))
			var data = api.UnloadRsaPrivateKey(privKey)
			if data, er1 = api.EncryptAesV1(data, teamKey); er1 == nil {
				r.PrivateKey = api.Base64UrlEncode(data)
				if x.EncryptedTeamKey, er1 = api.EncryptAesV2(teamKey, treeKey); er1 == nil {
					r.EncryptedTeamKey = api.Base64UrlEncode(x.EncryptedTeamKey)
					if data, er1 = api.EncryptAesV1(teamKey, loader.KeeperAuth().AuthContext().DataKey()); er1 == nil {
						r.TeamKey = api.Base64UrlEncode(data)
					}
				}
			}
		}
		if er1 == nil {
			requests = append(requests, r)
		} else {
			if onError != nil {
				onError(x.TeamUid, er1)
			} else {
				logger.Warn("\"team_add\" prepare error",
					zap.String("team_uid", api.Base64UrlEncode(x.TeamUid)), zap.Error(er1))
			}
		}
	}
	for _, x := range teamsToUpdate {
		var t = json_commands.EnterpriseTeam{
			TeamUid:       api.Base64UrlEncode(x.TeamUid),
			TeamName:      x.Name,
			RestrictShare: x.RestrictShare,
			RestrictEdit:  x.RestrictEdit,
			RestrictView:  x.RestrictView,
		}
		if x.NodeId > 0 {
			t.NodeId = new(int64)
			*t.NodeId = x.NodeId
		}
		var r = &json_commands.EnterpriseTeamUpdateCommand{
			EnterpriseTeam: t,
		}
		requests = append(requests, r)
	}
	for _, x := range teamsToDelete {
		var r = &json_commands.EnterpriseTeamDeleteCommand{
			TeamUid: api.Base64UrlEncode(x),
		}
		requests = append(requests, r)
	}
	var rss []*auth.KeeperApiResponse
	rss, err = loader.KeeperAuth().ExecuteBatch(requests)
	for i, x := range rss {
		if !x.IsSuccess() {
			var rq = requests[i]
			var teamUid string
			switch r := rq.(type) {
			case *json_commands.EnterpriseTeamDeleteCommand:
				teamUid = r.TeamUid
			case *json_commands.EnterpriseTeamAddCommand:
				teamUid = r.TeamUid
			case *json_commands.EnterpriseTeamUpdateCommand:
				teamUid = r.TeamUid
			}
			er1 = api.NewKeeperApiError(x.ResultCode, x.Message)
			if len(teamUid) > 0 {
				if onError != nil {
					onError(api.Base64UrlDecode(teamUid), er1)
				} else {
					logger.Warn("\"execute\" team batch error", zap.String("command", x.Command),
						zap.String("team_uid", teamUid), zap.Error(er1))
				}
			} else {
				logger.Warn("\"execute\" team batch error", zap.String("command", x.Command),
					zap.String("team_uid", "INVALID"), zap.Error(er1))
			}
		}
	}
	return
}
