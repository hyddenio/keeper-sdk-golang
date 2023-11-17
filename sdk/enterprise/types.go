package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
)

type INode interface {
	NodeId() int64
	Name() string
	ParentId() int64
	BridgeId() int64
	ScimId() int64
	LicenseId() int64
	DuoEnabled() bool
	RsaEnabled() bool
	RestrictVisibility() bool
	SsoServiceProviderId() []int64
	EncryptedData() string
}

type INodeEdit interface {
	INode
	SetName(string)
	SetParentId(int64)
	SetRestrictVisibility(bool)
}

type IRole interface {
	RoleId() int64
	Name() string
	NodeId() int64
	KeyType() string
	VisibleBelow() bool
	NewUserInherit() bool
	RoleType() string
	EncryptedData() string
}

type IRoleEdit interface {
	IRole
	SetName(string)
	SetNodeId(int64)
	SetKeyType(string)
	SetVisibleBelow(bool)
	SetNewUserInherit(bool)
}

type IUser interface {
	EnterpriseUserId() int64
	Username() string
	FullName() string
	JobTitle() string
	NodeId() int64
	Status() string
	Lock() int32
	UserId() int32
	AccountShareExpiration() int64
	TfaEnabled() bool
	TransferAcceptanceStatus() int32
}

type ITeam interface {
	TeamUid() string
	Name() string
	NodeId() int64
	RestrictEdit() bool
	RestrictShare() bool
	RestrictView() bool
	EncryptedTeamKey() []byte
}

type ITeamEdit interface {
	ITeam
	SetName(string)
	SetNodeId(int64)
	SetRestrictEdit(bool)
	SetRestrictShare(bool)
	SetRestrictView(bool)
}

type ITeamUser interface {
	TeamUid() string
	EnterpriseUserId() int64
	UserType() string
}

type IRoleUser interface {
	RoleId() int64
	EnterpriseUserId() int64
}

type IRolePrivilege interface {
	RoleId() int64
	ManagedNodeId() int64
	Privileges() []string
}
type IRolePrivilegeEdit interface {
	IRolePrivilege
	SetPrivilege(string)
	RemovePrivilege(string)
}
type IManagedNode interface {
	RoleId() int64
	ManagedNodeId() int64
	CascadeNodeManagement() bool
}

type IRoleEnforcement interface {
	RoleId() int64
	Enforcements() map[string]string
}

type IEnterpriseStorage interface {
	ContinuationToken() ([]byte, error)
	SetContinuationToken([]byte) error
	GetEntities(func(int32, []byte) bool) error
	PutEntity(int32, string, []byte) error
	DeleteEntity(int32, string) error
	Flush() error
	Clear()
}

type IEnterpriseInfo interface {
	EnterpriseName() string
	IsDistributor() bool
	TreeKey() []byte
	RsaPrivateKey() *rsa.PrivateKey
	EcPrivateKey() *ecdh.PrivateKey
}

type IEnterpriseEntity[T interface{}, K comparable] interface {
	GetAllEntities(func(T) bool)
	GetEntity(K) T
}

type IEnterpriseLink[T interface{}, KS comparable, KO comparable] interface {
	GetLink(KS, KO) T
	GetLinksBySubject(KS, func(T) bool)
	GetLinksByObject(KO, func(T) bool)
	GetAllLinks(func(T) bool)
}

type IEnterpriseData interface {
	EnterpriseInfo() IEnterpriseInfo
	Nodes() IEnterpriseEntity[INode, int64]
	Roles() IEnterpriseEntity[IRole, int64]
	Users() IEnterpriseEntity[IUser, int64]
	Teams() IEnterpriseEntity[ITeam, string]
	TeamUsers() IEnterpriseLink[ITeamUser, string, int64]
	RoleUsers() IEnterpriseLink[IRoleUser, int64, int64]
	RolePrivileges() IEnterpriseLink[IRolePrivilege, int64, int64]
	//RoleEnforcements() map[int64]*RoleEnforcement
	//ManagedNodes() map[int64][]*ManagedNode
	//GetRoleKey(roleId int64) []byte
	GetRootNode() INode
}

type IEnterpriseLoader interface {
	Storage() IEnterpriseStorage
	EnterpriseData() IEnterpriseData
	KeeperAuth() auth.IKeeperAuth
	Load() error
}

const (
	RolePrivilege_ManageNodes          = "MANAGE_NODES"
	RolePrivilege_ManageUsers          = "MANAGE_USER"
	RolePrivilege_ManageLicences       = "MANAGE_LICENCES"
	RolePrivilege_ManageRoles          = "MANAGE_ROLES"
	RolePrivilege_ManageTeams          = "MANAGE_TEAMS"
	RolePrivilege_RunSecurityReports   = "RUN_REPORTS"
	RolePrivilege_ManageBridge         = "MANAGE_BRIDGE"
	RolePrivilege_ApproveDevice        = "APPROVE_DEVICE"
	RolePrivilege_ManageRecordTypes    = "MANAGE_RECORD_TYPES"
	RolePrivilege_RunComplianceReports = "RUN_COMPLIANCE_REPORTS"
	RolePrivilege_ManageCompanies      = "MANAGE_COMPANIES"
	RolePrivilege_TransferAccount      = "TRANSFER_ACCOUNT"
	RolePrivilege_SharingAdministrator = "SHARING_ADMINISTRATOR"
)

var (
	rolePrivileges = [...]string{
		RolePrivilege_ManageNodes, RolePrivilege_ManageUsers, RolePrivilege_ManageLicences,
		RolePrivilege_ManageRoles, RolePrivilege_ManageTeams, RolePrivilege_RunSecurityReports,
		RolePrivilege_ManageBridge, RolePrivilege_ApproveDevice, RolePrivilege_ManageRecordTypes,
		RolePrivilege_RunComplianceReports, RolePrivilege_ManageCompanies, RolePrivilege_TransferAccount,
		RolePrivilege_SharingAdministrator,
	}
)

func AvailableRolePrivileges() []string {
	return rolePrivileges[:]
}

type IEnterpriseManagement interface {
	GetEnterpriseId() (int64, error)
	EnterpriseData() IEnterpriseData
	ModifyNodes(nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) []error
	ModifyRoles(rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) []error
	ModifyTeams(teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) []error
	ModifyTeamUsers(teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) []error
	//SetRolePrivileges(privileges []IRolePrivilege) error
}
