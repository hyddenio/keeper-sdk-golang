package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_enterprise"
	"google.golang.org/protobuf/proto"
)

type Node struct {
	NodeId               int64
	Name                 string
	ParentId             int64
	BridgeId             int64
	ScimId               int64
	LicenseId            int64
	DuoEnabled           bool
	RsaEnabled           bool
	SsoServiceProviderId []int64
}

type Role struct {
	RoleId         int64
	Name           string
	NodeId         int64
	KeyType        string
	VisibleBelow   bool
	NewUserInherit bool
	RoleType       string
}

type User struct {
	EnterpriseUserId         int64
	Username                 string
	FullName                 string
	JobTitle                 string
	NodeId                   int64
	Status                   string
	Lock                     int32
	UserId                   int32
	AccountShareExpiration   int64
	TfaEnabled               bool
	TransferAcceptanceStatus int32
}

type Team struct {
	TeamUid          []byte
	Name             string
	NodeId           int64
	RestrictEdit     bool
	RestrictShare    bool
	RestrictView     bool
	EncryptedTeamKey []byte
}

type TeamUser struct {
	TeamUid          []byte
	EnterpriseUserId int64
	UserType         string
}

type RoleUser struct {
	RoleId           int64
	EnterpriseUserId int64
}

type ManagedNode struct {
	RoleId                int64
	ManagedNodeId         int64
	CascadeNodeManagement bool
}

type RoleEnforcement struct {
	RoleId      int64
	Enforcement map[string]string
}

type IEnterpriseStorage interface {
	ContinuationToken() []byte
	SetContinuationToken([]byte)
	GetEntities(func(int32, []byte) bool) error
	PutEntity(int32, string, []byte) error
	DeleteEntity(int32, string) error
	Flush()
	Clear()
}

type IEnterpriseInfo interface {
	EnterpriseName() string
	IsDistributor() bool
	TreeKey() []byte
	RsaPrivateKey() *rsa.PrivateKey
	EcPrivateKey() *ecdh.PrivateKey
}

type IEnterprisePlugin interface {
	NewEntity(data []byte) (proto.Message, error)
	Store(proto.Message, []byte)
	Delete(proto.Message)
	Clear()
}

type IEnterpriseEntity[T any] interface {
	IEnterprisePlugin
	GetData() map[int64]*T
}

type IEnterpriseLink[T any] interface {
	IEnterprisePlugin
	GetData() map[[2]int64]*T
	CascadeDelete(int64)
}

type IEnterpriseData interface {
	EnterpriseInfo() IEnterpriseInfo
	Nodes() IEnterpriseEntity[Node]
	Roles() IEnterpriseEntity[Role]
	Users() IEnterpriseEntity[User]
	Teams() IEnterpriseEntity[Team]
	TeamUsers() IEnterpriseLink[TeamUser]
	//RoleUsers() map[int64][]*RoleUser
	//RolePrivileges() map[int64]map[int64][]string
	//ManagedNodes() map[int64][]*ManagedNode
	//RoleEnforcements() map[int64]*RoleEnforcement
	//GetRoleKey(roleId int64) []byte
	GetRootNode() *Node

	GetSupportedEntities() []proto_enterprise.EnterpriseDataEntity
	GetEnterprisePlugin(proto_enterprise.EnterpriseDataEntity) IEnterprisePlugin
}

type IEnterpriseLoader interface {
	Storage() IEnterpriseStorage
	EnterpriseData() IEnterpriseData
	KeeperAuth() auth.IKeeperAuth
	Load() error
}
