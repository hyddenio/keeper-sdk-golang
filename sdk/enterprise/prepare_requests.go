package enterprise

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/json_commands"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_auth"
	"strings"
)

type EncryptedData struct {
	DisplayName string `json:"displayname,omitempty"`
}

func parseEncryptedData(encryptedData string, treeKey []byte) (result *EncryptedData, err error) {
	if len(encryptedData) > 0 {
		var data = api.Base64UrlDecode(encryptedData)
		if data, err = api.DecryptAesV1(data, treeKey); err == nil {
			err = json.Unmarshal(data, &result)
		}
	} else {
		err = api.NewKeeperError("Encrypted data is empty")
	}
	return
}

func createEncryptedData(encData *EncryptedData, oldData string, treeKey []byte) (result string, err error) {
	var data []byte
	if data, err = json.Marshal(encData); err != nil {
		return
	}
	if len(oldData) > 0 {
		var ed = make(map[string]any)
		var eData = api.Base64UrlDecode(oldData)
		if eData, err = api.DecryptAesV1(eData, treeKey); err == nil {
			if err = json.Unmarshal(eData, &ed); err == nil {
				if eData, err = json.Marshal(ed); err == nil {
					data = eData
				}
			}
		}
	}
	if data, err = api.EncryptAesV1(data, treeKey); err != nil {
		return
	}
	result = api.Base64UrlEncode(data)
	return
}

func prepareTeamRequests(loader IEnterpriseLoader, teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) (requests []auth.IKeeperCommand, errs []error) {
	var eData = loader.EnterpriseData()

	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var teams = loader.EnterpriseData().Teams()
	var dataKey = loader.KeeperAuth().AuthContext().DataKey()

	var err error
	var data []byte
	for _, x := range teamsToAdd {
		var teamUid = x.TeamUid()
		if len(teamUid) == 0 {
			err = errors.New(fmt.Sprintf("team \"%s\" does not have TeamUID assigned", x.Name()))
			continue
		}
		var t = json_commands.EnterpriseTeam{
			TeamUid:       teamUid,
			TeamName:      x.Name(),
			RestrictShare: x.RestrictShare(),
			RestrictEdit:  x.RestrictEdit(),
			RestrictView:  x.RestrictView(),
		}
		t.NodeId = new(int64)
		if x.NodeId() > 0 {
			*t.NodeId = x.NodeId()
		} else {
			*t.NodeId = eData.GetRootNode().NodeId()
		}
		var r = &json_commands.EnterpriseTeamAddCommand{
			EnterpriseTeam: t,
		}

		var teamKey = api.GenerateAesKey()
		var privKey *rsa.PrivateKey
		var pubKey *rsa.PublicKey
		if privKey, pubKey, err = api.GenerateRsaKey(); err != nil {
			errs = append(errs, err)
			continue
		}
		r.PublicKey = api.Base64UrlEncode(api.UnloadRsaPublicKey(pubKey))

		data = api.UnloadRsaPrivateKey(privKey)
		if data, err = api.EncryptAesV1(data, teamKey); err != nil {
			errs = append(errs, err)
			continue
		}
		r.PrivateKey = api.Base64UrlEncode(data)

		if data, err = api.EncryptAesV2(teamKey, treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		r.EncryptedTeamKey = api.Base64UrlEncode(data)

		if data, err = api.EncryptAesV1(teamKey, dataKey); err != nil {
			errs = append(errs, err)
			continue
		}
		r.TeamKey = api.Base64UrlEncode(data)

		requests = append(requests, r)
	}
	for _, x := range teamsToUpdate {
		var existingTeam = teams.GetEntity(x.TeamUid())
		if existingTeam == nil {
			err = errors.New(fmt.Sprintf("update team: UID \"%s\" not found", x.TeamUid()))
			errs = append(errs, err)
			continue
		}
		var t = json_commands.EnterpriseTeam{
			TeamUid:       x.TeamUid(),
			TeamName:      x.Name(),
			RestrictShare: x.RestrictShare(),
			RestrictEdit:  x.RestrictEdit(),
			RestrictView:  x.RestrictView(),
		}
		t.NodeId = new(int64)
		*t.NodeId = x.NodeId()
		var r = &json_commands.EnterpriseTeamUpdateCommand{
			EnterpriseTeam: t,
		}
		requests = append(requests, r)
	}

	for _, teamUid := range teamsToDelete {
		var existingTeam = teams.GetEntity(teamUid)
		if existingTeam == nil {
			err = errors.New(fmt.Sprintf("delete team: UID \"%s\" not found", teamUid))
			errs = append(errs, err)
			continue
		}
		var r = &json_commands.EnterpriseTeamDeleteCommand{
			TeamUid: teamUid,
		}
		requests = append(requests, r)
	}
	return
}

func prepareNodeRequests(loader IEnterpriseLoader, nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) (requests []auth.IKeeperCommand, errs []error) {
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var nodes = loader.EnterpriseData().Nodes()

	var err error

	for _, x := range nodesToAdd {
		if x.NodeId() == 0 {
			err = errors.New(fmt.Sprintf("Node \"%s\" does not have NodeID", x.Name()))
			errs = append(errs, err)
			continue
		}
		var nodeData = &EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(nodeData, "", treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var nac = &json_commands.EnterpriseNodeAddCommand{
			EnterpriseNode: json_commands.EnterpriseNode{
				NodeId:        x.NodeId(),
				ParentId:      x.ParentId(),
				EncryptedData: encryptedData,
			},
		}
		if x.RestrictVisibility() {
			nac.RestrictVisibility = new(string)
			*nac.RestrictVisibility = "1"
		}
		requests = append(requests, nac)
	}
	for _, x := range nodesToUpdate {
		var existingNode = nodes.GetEntity(x.NodeId())
		if existingNode == nil {
			err = errors.New(fmt.Sprintf("node UID \"%d\" does not exist", x.NodeId()))
			errs = append(errs, err)
			continue
		}

		var nodeData = &EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(nodeData, existingNode.EncryptedData(), treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var nuc = &json_commands.EnterpriseNodeUpdateCommand{
			EnterpriseNode: json_commands.EnterpriseNode{
				NodeId:        x.NodeId(),
				ParentId:      x.ParentId(),
				EncryptedData: encryptedData,
			},
		}
		requests = append(requests, nuc)
	}

	for _, nodeId := range nodesToDelete {
		var existingNode = nodes.GetEntity(nodeId)
		if existingNode == nil {
			err = errors.New(fmt.Sprintf("team UID \"%d\" does not exist", nodeId))
			errs = append(errs, err)
			continue
		}

		var r = &json_commands.EnterpriseNodeDeleteCommand{
			NodeId: nodeId,
		}
		requests = append(requests, r)
	}
	return
}

func prepareRoleRequests(loader IEnterpriseLoader, rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) (requests []auth.IKeeperCommand, errs []error) {
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var roles = loader.EnterpriseData().Roles()

	var err error

	for _, x := range rolesToAdd {
		if x.RoleId() == 0 {
			err = errors.New(fmt.Sprintf("Role \"%s\" does not have ID assigned", x.Name()))
			errs = append(errs, err)
			continue
		}
		var roleData = &EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(roleData, "", treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var rac = &json_commands.EnterpriseRoleAddCommand{
			EnterpriseRole: json_commands.EnterpriseRole{
				RoleId:         x.RoleId(),
				NodeId:         new(int64),
				EncryptedData:  encryptedData,
				VisibleBelow:   new(bool),
				NewUserInherit: new(bool),
			},
		}
		if x.NodeId() > 0 {
			*rac.NodeId = x.NodeId()
		} else {
			*rac.NodeId = loader.EnterpriseData().GetRootNode().NodeId()
		}
		*rac.VisibleBelow = x.VisibleBelow()
		*rac.NewUserInherit = x.NewUserInherit()
		requests = append(requests, rac)
	}
	for _, x := range rolesToUpdate {
		var existingRole = roles.GetEntity(x.RoleId())
		if existingRole == nil {
			err = errors.New(fmt.Sprintf("role UID \"%d\" does not exist", x.RoleId()))
			errs = append(errs, err)
			continue
		}

		var roleData = &EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(roleData, existingRole.EncryptedData(), treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var ruc = &json_commands.EnterpriseRoleUpdateCommand{
			EnterpriseRole: json_commands.EnterpriseRole{
				RoleId:        x.RoleId(),
				EncryptedData: encryptedData,
			},
		}
		if x.NodeId() > 0 && x.NodeId() != existingRole.NodeId() {
			ruc.NodeId = new(int64)
			*ruc.NodeId = x.NodeId()
		}
		if x.VisibleBelow() != existingRole.VisibleBelow() {
			ruc.VisibleBelow = new(bool)
			*ruc.VisibleBelow = x.VisibleBelow()
		}
		if x.NewUserInherit() != existingRole.NewUserInherit() {
			ruc.NewUserInherit = new(bool)
			*ruc.NewUserInherit = x.NewUserInherit()
		}
		requests = append(requests, ruc)
	}

	for _, roleId := range rolesToDelete {
		var existingRole = roles.GetEntity(roleId)
		if existingRole == nil {
			err = errors.New(fmt.Sprintf("role UID \"%d\" does not exist", roleId))
			errs = append(errs, err)
			continue
		}

		var r = &json_commands.EnterpriseRoleDeleteCommand{
			RoleId: roleId,
		}
		requests = append(requests, r)
	}
	return
}

func prepareTeamUserRequests(loader IEnterpriseLoader, teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) (
	addRequests []*proto_auth.UserTeamKey, requests []auth.IKeeperCommand, errs []error) {

	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var teamUsers = loader.EnterpriseData().TeamUsers()
	var users = loader.EnterpriseData().Users()
	var teams = loader.EnterpriseData().Teams()
	var userKeys = make(map[string]*auth.PublicKeys)
	var teamKeys = make(map[string][]byte)
	var toAdd []ITeamUser
	var toUpdate []ITeamUser

	var err error
	var tu ITeamUser
	for _, tu = range teamUsersToAdd {
		var t = teams.GetEntity(tu.TeamUid())
		if t == nil {
			err = errors.New(fmt.Sprintf("team-user: team UID \"%s\" not found", tu.TeamUid()))
			errs = append(errs, err)
			continue
		}
		var u = users.GetEntity(tu.EnterpriseUserId())
		if u == nil {
			err = errors.New(fmt.Sprintf("team-user: user ID \"%d\" not found", tu.EnterpriseUserId()))
			errs = append(errs, err)
			continue
		}
		if u.Status() != "active" {
			err = errors.New(fmt.Sprintf("team-user: user \"%s\" is not active", u.Username()))
			errs = append(errs, err)
			continue
		}
		var otu = teamUsers.GetLink(tu.TeamUid(), tu.EnterpriseUserId())
		if otu == nil {
			toAdd = append(toAdd, tu)
			userKeys[u.Username()] = nil
			teamKeys[otu.TeamUid()] = nil
		} else {
			toUpdate = append(toUpdate, tu)
		}
	}
	if len(userKeys) > 0 {
		for _, err = range auth.GetUserPublicKeys(loader.KeeperAuth(), userKeys) {
			errs = append(errs, err)
		}
	}
	if len(teamKeys) > 0 {
		var uids []string
		for k := range teamKeys {
			uids = append(uids, k)
		}
		var hasMissingKeys = false
		for _, uid := range uids {
			var t = teams.GetEntity(uid)
			if t != nil {
				if len(t.EncryptedTeamKey()) > 0 {
					var data []byte
					if data, err = api.DecryptAesV2(t.EncryptedTeamKey(), treeKey); err == nil {
						teamKeys[uid] = data
					} else {
						hasMissingKeys = true
					}
				} else {
					hasMissingKeys = true
				}
			}
		}
		if hasMissingKeys {
			errs = append(errs, auth.GetTeamKeys(loader.KeeperAuth(), teamKeys)...)
		}
	}

	for _, tu = range toAdd {
		var u = users.GetEntity(tu.EnterpriseUserId())
		if u != nil {
			var userKey = userKeys[u.Username()]
			var teamKey = teamKeys[tu.TeamUid()]
			if userKey != nil && teamKey != nil {
				var utk = &proto_auth.UserTeamKey{
					TeamUid:          api.Base64UrlDecode(tu.TeamUid()),
					Username:         u.Username(),
					EnterpriseUserId: u.EnterpriseUserId(),
				}
				if userKey.RsaPublicKey != nil {
					if utk.EncryptedTeamKeyRSA, err = api.EncryptRsa(teamKey, userKey.RsaPublicKey); err != nil {
						errs = append(errs, err)
					}
				}
				if userKey.EcPublicKey != nil {
					if utk.EncryptedTeamKeyEC, err = api.EncryptEc(teamKey, userKey.EcPublicKey); err != nil {
						errs = append(errs, err)
					}
				}
				addRequests = append(addRequests, utk)
			}
		}
	}

	for _, tu = range toUpdate {
		var rq = &json_commands.EnterpriseTeamUserUpdateCommand{
			EnterpriseTeamUser: json_commands.EnterpriseTeamUser{
				TeamUid:          tu.TeamUid(),
				EnterpriseUserId: tu.EnterpriseUserId(),
			},
		}
		switch strings.ToUpper(tu.UserType()) {
		case "ADMIN":
			rq.UserType = 1
			break
		case "ADMIN_ONLY":
			rq.UserType = 2
			break
		}
		requests = append(requests, rq)
	}

	for _, tu = range teamUsersToRemove {
		var ctu = teamUsers.GetLink(tu.TeamUid(), tu.EnterpriseUserId())
		if ctu == nil {
			err = errors.New(fmt.Sprintf("team=\"%s\" does not contain user=%d", tu.TeamUid(), tu.EnterpriseUserId()))
			errs = append(errs, err)
			continue
		}
		var rq = &json_commands.EnterpriseTeamUserRemoveCommand{
			EnterpriseTeamUser: json_commands.EnterpriseTeamUser{
				TeamUid:          tu.TeamUid(),
				EnterpriseUserId: tu.EnterpriseUserId(),
			},
		}
		requests = append(requests, rq)
	}

	return
}
