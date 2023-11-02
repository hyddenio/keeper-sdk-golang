package auth

type ICommand interface {
	Command() string
}
type KeeperApiCommand struct {
	Command       string `json:"command"`
	Locale        string `json:"locale"`
	ClientVersion string `json:"client_version"`
}
type ToKeeperApiCommand interface {
	GetKeeperApiCommand() *KeeperApiCommand
}

func (command *KeeperApiCommand) GetKeeperApiCommand() *KeeperApiCommand {
	return command
}

type KeeperApiResponse struct {
	Result     string `json:"result"`
	ResultCode string `json:"result_code"`
	Message    string `json:"message"`
	Command    string `json:"command"`
}
type ToKeeperApiResponse interface {
	GetKeeperApiResponse() *KeeperApiResponse
}

func (rs *KeeperApiResponse) GetKeeperApiResponse() *KeeperApiResponse {
	return rs
}

func (rs *KeeperApiResponse) IsSuccess() bool {
	return rs.Result == "success"
}

type KeeperApiErrorResponse struct {
	KeeperApiResponse
	Error          string `json:"error"`
	KeyId          int32  `json:"key_id"`
	RegionHost     string `json:"region_host"`
	AdditionalInfo string `json:"additional_info"`
}

type LoginCommand struct {
	KeeperApiCommand
	Version                  int32    `json:"version"`
	Include                  []string `json:"include"`
	AuthResponse             string   `json:"auth_response"`
	Username                 string   `json:"username"`
	TwoFactorType            string   `json:"2fa_type"`
	TwoFactorToken           string   `json:"2fa_token"`
	TwoFactorMode            string   `json:"2fa_mode"`
	DeviceTokenExpiresInDays *int32   `json:"device_token_expire_days"`
	PlatformDeviceToken      string   `json:platform_device_token`
}

func (c *LoginCommand) Command() string {
	return "login"
}

type AccountKeys struct {
	EncryptionParams    string  `json:"encryption_params"`
	EncryptedDataKey    string  `json:"encrypted_data_key"`
	EncryptedPrivateKey string  `json:"encrypted_private_key"`
	DataKeyBackupDate   float64 `json:"data_key_backup_date"`
}

type PasswordRules struct {
	Match       bool   `json:"match"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

type AccountEnforcements struct {
	PasswordRulesIntro string           `json:"password_rules_intro"`
	PasswordRules      []*PasswordRules `json:"password_rules"`
}

type AccountShareTo struct {
	RoleId    int64  `json:"role_id"`
	PublicKey string `json:"public_key"`
}

type AccountLicense struct {
	AccountType                   int32   `json:"account_type"`
	ProductTypeId                 int32   `json:"product_type_id"`
	ProductTypeName               string  `json:"product_type_name"`
	ExpirationDate                string  `json:"expiration_date"`
	SecondsUntilExpiration        float64 `json:"seconds_until_expiration"`
	FilePlanType                  int32   `json:"file_plan_type"`
	StorageExpirationDate         string  `json:"storage_expiration_date"`
	SecondsUntilStorageExpiration float64 `json:"seconds_until_storage_expiration"`
}

type AccountSettings struct {
	PasswordRulesIntro         string            `json:"password_rules_intro"`
	PasswordRules              []*PasswordRules  `json:"password_rules"`
	Channel                    string            `json:"channel"`
	SsoUser                    *bool             `json:"sso_user"`
	MustPerformAccountShareBy  *float64          `json:"must_perform_account_share_by"`
	ShareAccountTo             []*AccountShareTo `json:"share_account_to"`
	MasterPasswordLastModified *float64          `json:"master_password_last_modified"`
	EmailVerified              bool              `json:"email_verified"`
}

type LoginResponse struct {
	KeeperApiResponse
	SessionToken      string               `json:"session_token"`
	DeviceToken       string               `json:"device_token"`
	DtScope           string               `json:"dt_scope"`
	Channel           string               `json:"channel"`
	Capabilities      []string             `json:"capabilities"`
	Phone             string               `json:"phone"`
	Url               string               `json:"url"`
	EnrollUrl         string               `json:"enroll_url"`
	ClientKey         string               `json:"client_key"`
	IsEnterpriseAdmin *bool                `json:"is_enterprise_admin"`
	Settings          *AccountSettings     `json:"settings"`
	License           *AccountLicense      `json:"license"`
	Keys              *AccountKeys         `json:"keys"`
	Enforcements      *AccountEnforcements `json:"enforcements"`
	Iterations        int32                `json:"iterations"`
	Salt              string               `json:"salt"`
}

type AuthorizedCommand struct {
	KeeperApiCommand
	SessionToken string `json:"session_token"`
	Username     string `json:"username"`
}
type ToAuthorizedCommand interface {
	GetAuthorizedCommand() *AuthorizedCommand
}

func (command *AuthorizedCommand) GetAuthorizedCommand() *AuthorizedCommand {
	return command
}

type SetClientKeyCommand struct {
	AuthorizedCommand
	ClientKey string `json:"client_key"`
}

func (c *SetClientKeyCommand) Command() string {
	return "set_client_key"
}

type SetClientKeyResponse struct {
	KeeperApiResponse
	ClientKey string `json:"client_key"`
}

type ChangeMasterPasswordCommand struct {
	AuthorizedCommand
	AuthVerifier     string `json:"auth_verifier"`
	EncryptionParams string `json:"encryption_params"`
}

func (c *ChangeMasterPasswordCommand) Command() string {
	return "change_master_password"
}

type ShareAccountCommand struct {
	AuthorizedCommand
	ToRoleId    int64  `json:"to_role_id"`
	TransferKey string `json:"transfer_key"`
}

func (c *ShareAccountCommand) Command() string {
	return "share_account"
}
