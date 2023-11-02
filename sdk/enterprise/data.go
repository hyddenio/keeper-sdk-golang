package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_enterprise"
	"google.golang.org/protobuf/proto"
)

var (
	_ IEnterpriseData = &enterpriseData{}
)

type enterpriseInfo struct {
	enterpriseName string
	treeKey        []byte
	rsaPrivateKey  *rsa.PrivateKey
	ecPrivateKey   *ecdh.PrivateKey
	isDistributor  bool
}

func (ei *enterpriseInfo) IsDistributor() bool {
	return ei.isDistributor
}
func (ei *enterpriseInfo) EnterpriseName() string {
	return ei.enterpriseName
}
func (ei *enterpriseInfo) TreeKey() []byte {
	return ei.treeKey
}
func (ei *enterpriseInfo) RsaPrivateKey() *rsa.PrivateKey {
	return ei.rsaPrivateKey
}
func (ei *enterpriseInfo) EcPrivateKey() *ecdh.PrivateKey {
	return ei.ecPrivateKey
}

type enterpriseData struct {
	enterpriseInfo      *enterpriseInfo
	enterpriseDataTypes map[proto_enterprise.EnterpriseDataEntity]IEnterprisePlugin
	rootNode            *Node
}

func (ed *enterpriseData) GetRootNode() *Node {
	if ed.rootNode == nil {
		for _, n := range ed.Nodes().GetData() {
			if n.ParentId == 0 {
				ed.rootNode = n
				break
			}
		}
	}
	return ed.rootNode
}

func (ed *enterpriseData) EnterpriseInfo() IEnterpriseInfo {
	return ed.enterpriseInfo
}

func (ed *enterpriseData) GetSupportedEntities() (res []proto_enterprise.EnterpriseDataEntity) {
	for k := range ed.enterpriseDataTypes {
		res = append(res, k)
	}
	return
}

func (ed *enterpriseData) GetEnterprisePlugin(entityType proto_enterprise.EnterpriseDataEntity) IEnterprisePlugin {
	return ed.enterpriseDataTypes[entityType]
}

func (ed *enterpriseData) PutEntity(entityType proto_enterprise.EnterpriseDataEntity, entity proto.Message) {
	var ok bool
	var baseDataType IEnterprisePlugin
	if baseDataType, ok = ed.enterpriseDataTypes[entityType]; ok {
		baseDataType.Store(entity, ed.EnterpriseInfo().TreeKey())
	}
}
func (ed *enterpriseData) DeleteEntity(entityType proto_enterprise.EnterpriseDataEntity, entity proto.Message) {
	var ok bool
	var baseDataType IEnterprisePlugin
	if baseDataType, ok = ed.enterpriseDataTypes[entityType]; ok {
		baseDataType.Delete(entity)
	}
}
func (ed *enterpriseData) Clear() {
	for _, v := range ed.enterpriseDataTypes {
		v.Clear()
	}
}
func (ed *enterpriseData) Nodes() IEnterpriseEntity[Node] {
	if bt := ed.GetEnterprisePlugin(proto_enterprise.EnterpriseDataEntity_NODES); bt != nil {
		if ne, ok := bt.(IEnterpriseEntity[Node]); ok {
			return ne
		}
	}
	return nil
}
func (ed *enterpriseData) Roles() IEnterpriseEntity[Role] {
	if bt := ed.GetEnterprisePlugin(proto_enterprise.EnterpriseDataEntity_ROLES); bt != nil {
		if ne, ok := bt.(IEnterpriseEntity[Role]); ok {
			return ne
		}
	}
	return nil
}

func (ed *enterpriseData) Users() IEnterpriseEntity[User] {
	if bt := ed.GetEnterprisePlugin(proto_enterprise.EnterpriseDataEntity_USERS); bt != nil {
		if ue, ok := bt.(IEnterpriseEntity[User]); ok {
			return ue
		}
	}
	return nil
}

func (ed *enterpriseData) Teams() IEnterpriseEntity[Team] {
	if bt := ed.GetEnterprisePlugin(proto_enterprise.EnterpriseDataEntity_TEAMS); bt != nil {
		if ue, ok := bt.(IEnterpriseEntity[Team]); ok {
			return ue
		}
	}
	return nil
}

func (ed *enterpriseData) TeamUsers() IEnterpriseLink[TeamUser] {
	if bt := ed.GetEnterprisePlugin(proto_enterprise.EnterpriseDataEntity_TEAM_USERS); bt != nil {
		if ue, ok := bt.(IEnterpriseLink[TeamUser]); ok {
			return ue
		}
	}
	return nil
}

func newEnterpriseData(ei *enterpriseInfo) *enterpriseData {
	var ed = &enterpriseData{
		enterpriseInfo:      ei,
		enterpriseDataTypes: make(map[proto_enterprise.EnterpriseDataEntity]IEnterprisePlugin),
	}

	ed.enterpriseDataTypes[proto_enterprise.EnterpriseDataEntity_NODES] = newNodeEntity()
	ed.enterpriseDataTypes[proto_enterprise.EnterpriseDataEntity_ROLES] = newRoleEntity()
	ed.enterpriseDataTypes[proto_enterprise.EnterpriseDataEntity_USERS] = newUserEntity()
	ed.enterpriseDataTypes[proto_enterprise.EnterpriseDataEntity_TEAMS] = newTeamEntity()
	ed.enterpriseDataTypes[proto_enterprise.EnterpriseDataEntity_TEAM_USERS] = newTeamUserEntity()

	return ed
}
