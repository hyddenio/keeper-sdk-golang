package enterprise

import (
	"errors"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/json_commands"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_auth"
	"google.golang.org/protobuf/proto"
	"sync"
)

func NewSyncEnterpriseManagement(loader IEnterpriseLoader) IEnterpriseManagement {
	return &syncEnterpriseManagement{
		loader: loader,
	}
}

type syncEnterpriseManagement struct {
	loader        IEnterpriseLoader
	enterpriseIds []int64
	lock          sync.Mutex
}

func (sem *syncEnterpriseManagement) EnterpriseData() IEnterpriseData {
	return sem.loader.EnterpriseData()
}

func (sem *syncEnterpriseManagement) GetEnterpriseId() (id int64, err error) {
	sem.lock.Lock()
	defer sem.lock.Unlock()

	if len(sem.enterpriseIds) == 0 {
		var ids []int64
		if ids, err = GetEnterpriseIds(sem.loader.KeeperAuth(), 2); err != nil {
			return
		}
		sem.enterpriseIds = append(sem.enterpriseIds, ids...)
	}
	id = sem.enterpriseIds[0]
	sem.enterpriseIds = sem.enterpriseIds[1:]
	return
}

func (sem *syncEnterpriseManagement) ModifyNodes(nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) (errs []error) {
	var requests []auth.IKeeperCommand
	requests, errs = prepareNodeRequests(sem.loader, nodesToAdd, nodesToUpdate, nodesToDelete)

	var err error
	var rss []*auth.KeeperApiResponse
	if rss, err = sem.loader.KeeperAuth().ExecuteBatch(requests); err != nil {
		errs = append(errs, err)
		return
	}

	for i, x := range rss {
		if !x.IsSuccess() {
			var rq = requests[i]
			var nodeId int64
			switch r := rq.(type) {
			case *json_commands.EnterpriseNodeDeleteCommand:
				nodeId = r.NodeId
			case *json_commands.EnterpriseNodeAddCommand:
				nodeId = r.NodeId
			case *json_commands.EnterpriseNodeUpdateCommand:
				nodeId = r.NodeId
			}
			var message = x.Message
			if nodeId > 0 {
				message += fmt.Sprintf("; command=\"%s\"; nodeID=%d", rq.CommandName(), nodeId)
			}
			err = api.NewKeeperApiError(x.ResultCode, message)
			errs = append(errs, err)
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyTeams(teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) (errs []error) {
	var requests []auth.IKeeperCommand
	requests, errs = prepareTeamRequests(sem.loader, teamsToAdd, teamsToUpdate, teamsToDelete)

	var err error
	var rss []*auth.KeeperApiResponse
	if rss, err = sem.loader.KeeperAuth().ExecuteBatch(requests); err != nil {
		errs = append(errs, err)
		return
	}

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
			var message = x.Message
			if len(teamUid) > 0 {
				message += fmt.Sprintf("; teamUID=\"%s\"", teamUid)
			}
			err = api.NewKeeperApiError(x.ResultCode, message)
			errs = append(errs, err)
			continue
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyRoles(rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) (errs []error) {
	var requests []auth.IKeeperCommand
	requests, errs = prepareRoleRequests(sem.loader, rolesToAdd, rolesToUpdate, rolesToDelete)

	var err error
	var rss []*auth.KeeperApiResponse
	if rss, err = sem.loader.KeeperAuth().ExecuteBatch(requests); err != nil {
		errs = append(errs, err)
		return
	}

	for i, x := range rss {
		if !x.IsSuccess() {
			var rq = requests[i]
			var roleId int64
			switch r := rq.(type) {
			case *json_commands.EnterpriseRoleDeleteCommand:
				roleId = r.RoleId
			case *json_commands.EnterpriseRoleAddCommand:
				roleId = r.RoleId
			case *json_commands.EnterpriseRoleUpdateCommand:
				roleId = r.RoleId
			}
			var message = x.Message
			if roleId > 0 {
				message += fmt.Sprintf("; roleID=\"%d\"", roleId)
			}
			err = api.NewKeeperApiError(x.ResultCode, message)
			errs = append(errs, err)
			continue
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyTeamUsers(teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) (errs []error) {
	var jsonRequests []auth.IKeeperCommand
	var addUserTeams []*proto_auth.UserTeamKey
	addUserTeams, jsonRequests, errs = prepareTeamUserRequests(sem.loader, teamUsersToAdd, teamUsersToRemove)

	var data []byte
	var err error
	for len(addUserTeams) > 0 {
		var chunk []*proto_auth.UserTeamKey
		if len(addUserTeams) >= 1000 {
			chunk = addUserTeams[:999]
			addUserTeams = append(([]*proto_auth.UserTeamKey)(nil), addUserTeams[999:]...)
		} else {
			chunk = addUserTeams
			addUserTeams = nil
		}
		var rq = new(proto_auth.GenericRequestResponse)
		for _, m := range chunk {
			if data, err = proto.Marshal(m); err == nil {
				rq.Request = append(rq.Request, data)
			} else {
				errs = append(errs, err)
			}
		}
		var rs = new(proto_auth.GenericRequestResponse)
		if err = sem.loader.KeeperAuth().ExecuteAuthRest("enterprise/user_team_key", rq, rs); err != nil {
			errs = append(errs, err)
			return
		}
		for _, data = range rs.Request {
			var m = new(proto_auth.UserTeamKey)
			if err = proto.Unmarshal(data, m); err == nil {
				if m.Status != proto_auth.GenericStatus_SUCCESS {
					if m.Status != proto_auth.GenericStatus_ALREADY_EXISTS {
						err = errors.New(fmt.Sprintf("error \"%s\" adding user \"%d\" to team \"%s\"",
							m.Status.String(), m.EnterpriseUserId, m.TeamUid))
						errs = append(errs, err)
					}
				}
			}
		}
	}

	if len(jsonRequests) > 0 {
		var rss []*auth.KeeperApiResponse
		if rss, err = sem.loader.KeeperAuth().ExecuteBatch(jsonRequests); err != nil {
			errs = append(errs, err)
			return
		}
		for i, x := range rss {
			if !x.IsSuccess() {
				var rq = jsonRequests[i]
				var teamUid string
				var userId int64
				switch r := rq.(type) {
				case *json_commands.EnterpriseTeamUserUpdateCommand:
					teamUid = r.TeamUid
					userId = r.EnterpriseUserId
				case *json_commands.EnterpriseTeamUserRemoveCommand:
					teamUid = r.TeamUid
					userId = r.EnterpriseUserId
				default:
					continue
				}
				var message = x.Message
				if userId > 0 {
					message += fmt.Sprintf("; teamUID=\"%s\"; UserID=\"%d\"", teamUid, userId)
				}
				err = api.NewKeeperApiError(x.ResultCode, message)
				errs = append(errs, err)
				continue
			}
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}

	return
}
