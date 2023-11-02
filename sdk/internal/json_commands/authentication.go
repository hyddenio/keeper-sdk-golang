package json_commands

import "github.com/keeper-security/keeper-sdk-golang/sdk/auth"

type ChangeMasterPasswordCommand struct {
	auth.AuthorizedCommand
	AuthVerifier     string `json:"auth_verifier"`
	EncryptionParams string `json:"encryption_params"`
}

func (c *ChangeMasterPasswordCommand) CommandName() string {
	return "change_master_password"
}

type ShareAccountCommand struct {
	auth.AuthorizedCommand
	ToRoleId    int64  `json:"to_role_id"`
	TransferKey string `json:"transfer_key"`
}

func (c *ShareAccountCommand) CommandName() string {
	return "share_account"
}

type SsoToken struct {
	Command      string `json:"command"`
	Result       string `json:"result"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	NewPassword  string `json:"new_password"`
	ProviderName string `json:"provider_name"`
	SessionId    string `json:"session_id"`
	LoginToken   string `json:"login_token"`
}

type ExecuteCommand struct {
	auth.AuthorizedCommand
	Requests []auth.IKeeperCommand `json:"requests"`
}

func (c *ExecuteCommand) CommandName() string {
	return "execute"
}

type ExecuteResponse struct {
	auth.KeeperApiResponse
	Responses []*auth.KeeperApiResponse `json:"results"`
}
