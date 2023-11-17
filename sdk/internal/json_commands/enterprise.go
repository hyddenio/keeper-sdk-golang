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

type EnterpriseNode struct {
	NodeId             int64   `json:"node_id"`
	ParentId           int64   `json:"parent_id"`
	EncryptedData      string  `json:"encrypted_data"`
	RestrictVisibility *string `json:"restrict_visibility,omitempty"`
}
type EnterpriseNodeAddCommand struct {
	auth.AuthorizedCommand
	EnterpriseNode
}

func (c *EnterpriseNodeAddCommand) CommandName() string {
	return "node_add"
}

type EnterpriseNodeUpdateCommand struct {
	auth.AuthorizedCommand
	EnterpriseNode
}

func (c *EnterpriseNodeUpdateCommand) CommandName() string {
	return "node_update"
}

type EnterpriseNodeDeleteCommand struct {
	auth.AuthorizedCommand
	NodeId int64 `json:"node_id"`
}

func (c *EnterpriseNodeDeleteCommand) CommandName() string {
	return "node_delete"
}

type EnterpriseTeam struct {
	TeamUid       string `json:"team_uid"`
	TeamName      string `json:"team_name"`
	NodeId        *int64 `json:"node_id,omitempty"`
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

type EnterpriseRole struct {
	RoleId         int64  `json:"role_id"`
	EncryptedData  string `json:"encrypted_data"`
	NodeId         *int64 `json:"node_id,omitempty"`
	VisibleBelow   *bool  `json:"visible_below,omitempty"`
	NewUserInherit *bool  `json:"new_user_inherit,omitempty"`
}
type EnterpriseRoleAddCommand struct {
	auth.AuthorizedCommand
	EnterpriseRole
}

func (c *EnterpriseRoleAddCommand) CommandName() string {
	return "role_add"
}

type EnterpriseRoleUpdateCommand struct {
	auth.AuthorizedCommand
	EnterpriseRole
}

func (c *EnterpriseRoleUpdateCommand) CommandName() string {
	return "role_update"
}

type EnterpriseRoleDeleteCommand struct {
	auth.AuthorizedCommand
	RoleId int64 `json:"role_id"`
}

func (c *EnterpriseRoleDeleteCommand) CommandName() string {
	return "role_delete"
}

type EnterpriseTeamUser struct {
	TeamUid          string `json:"team_uid"`
	EnterpriseUserId int64  `json:"enterprise_user_id"`
}

type EnterpriseTeamUserUpdateCommand struct {
	auth.AuthorizedCommand
	EnterpriseTeamUser
	UserType int `json:"user_type"`
}

func (c *EnterpriseTeamUserUpdateCommand) CommandName() string {
	return "team_enterprise_user_update"
}

type EnterpriseTeamUserRemoveCommand struct {
	auth.AuthorizedCommand
	EnterpriseTeamUser
}

func (c *EnterpriseTeamUserRemoveCommand) CommandName() string {
	return "team_enterprise_user_remove"
}
