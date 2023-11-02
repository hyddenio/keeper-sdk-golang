package json_commands

import "github.com/keeper-security/keeper-sdk-golang/sdk/auth"

type EnterpriseAllocateIdsCommand struct {
	auth.AuthorizedCommand
	NumberRequested int `json:"number_requested"`
}

func (c *EnterpriseAllocateIdsCommand) CommandName() string {
	return "enterprise_allocate_ids"
}

type EnterpriseAllocateIdsResponse struct {
	auth.KeeperApiResponse
	NumberAllocated int   `json:"number_allocated"`
	BaseId          int64 `json:"base_id"`
}

type EnterpriseTeam struct {
	TeamUid       string `json:"team_uid"`
	TeamName      string `json:"team_name"`
	NodeId        *int64 `json:"node_id"`
	RestrictShare bool   `json:"restrict_share"`
	RestrictEdit  bool   `json:"restrict_edit"`
	RestrictView  bool   `json:"restrict_view"`
}

type EnterpriseTeamAddCommand struct {
	auth.AuthorizedCommand
	EnterpriseTeam
	PublicKey        string `json:"public_key"`
	PrivateKey       string `json:"private_key"`
	TeamKey          string `json:"team_key"`
	ManageOnly       bool   `json:"manage_only"`
	EncryptedTeamKey string `json:"encrypted_team_key"`
}

func (c *EnterpriseTeamAddCommand) CommandName() string {
	return "team_add"
}

type EnterpriseTeamUpdateCommand struct {
	auth.AuthorizedCommand
	EnterpriseTeam
}

func (c *EnterpriseTeamUpdateCommand) CommandName() string {
	return "team_update"
}

type EnterpriseTeamDeleteCommand struct {
	auth.AuthorizedCommand
	TeamUid string `json:"team_uid"`
}

func (c *EnterpriseTeamDeleteCommand) CommandName() string {
	return "team_delete"
}
