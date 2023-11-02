package enterprise

import (
	"encoding/json"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_enterprise"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"hash"
	"hash/crc64"
	"strconv"
	"strings"
	"sync"
)

var (
	_ IEnterpriseEntity[Node] = newNodeEntity()
)

type Key interface {
	int64 | [2]int64
}

var (
	hasher hash.Hash64 = crc64.New(crc64.MakeTable(crc64.ECMA))
	m      sync.Mutex
)

func getBytesHash(b []byte) (res int64) {
	m.Lock()
	hasher.Reset()
	_, _ = hasher.Write(b)
	res = int64(hasher.Sum64())
	m.Unlock()
	return
}

type baseStorage[TP any, TK any, K Key] struct {
	IEnterprisePlugin
	data            map[K]*TK
	onConvertEntity func(*TP, []byte) *TK
	onEntityKey     func(*TP) K
}

func (be *baseStorage[TP, TK, K]) Clear() {
	be.data = nil
}

func (be *baseStorage[TP, TK, K]) NewEntity(data []byte) (m proto.Message, err error) {
	var protoEntity = new(TP)
	var ok bool
	if m, ok = any(protoEntity).(proto.Message); ok {
		err = proto.Unmarshal(data, m)
	} else {
		err = api.NewKeeperError("Invalid proto message class")
	}
	return
}

func (be *baseStorage[TP, TK, K]) Store(protoEntity proto.Message, treeKey []byte) {
	if be.data == nil {
		be.data = make(map[K]*TK)
	}
	var p *TP
	var ok bool
	if p, ok = any(protoEntity).(*TP); ok {
		var keeperEntity = be.toKeeper(p, treeKey)
		var key = be.getKey(p)
		be.data[key] = keeperEntity
	} else {
		panic("Invalid enterprise entity")
	}
	return
}
func (be *baseStorage[TP, TK, K]) Delete(protoEntity proto.Message) {
	if be.data == nil {
		return
	}
	var p *TP
	var ok bool
	if p, ok = any(protoEntity).(*TP); ok {
		var key = be.getKey(p)
		delete(be.data, key)
	} else {
		panic("Invalid enterprise entity")
	}
	return
}

func (be *baseStorage[TP, TK, K]) toKeeper(protoEntity *TP, treeKey []byte) *TK {
	if be.onConvertEntity != nil {
		return be.onConvertEntity(protoEntity, treeKey)
	} else {
		panic("Not implemented")
	}
}

func (be *baseStorage[TP, TK, K]) getKey(protoEntity *TP) (key K) {
	if be.onEntityKey != nil {
		return be.onEntityKey(protoEntity)
	}
	panic("Not implemented")
}

func (be *baseStorage[TP, TK, K]) EnumerateData(cb func(*TK) bool) {
	if be.data != nil {
		for _, v := range be.data {
			if !cb(v) {
				break
			}
		}
	}
}

func (be *baseStorage[TP, TK, K]) GetData() map[K]*TK {
	return be.data
}

type baseEntity[TP any, TK any] struct {
	baseStorage[TP, TK, int64]
}

func (e *baseEntity[TP, TK]) GetEntities(cb func(*TK) bool) {
	for _, v := range e.data {
		if !cb(v) {
			break
		}
	}
}

func parseEncryptedData(encryptedData string, treeKey []byte) (m map[string]interface{}, err error) {
	if len(encryptedData) > 0 {
		var data []byte
		if data, err = api.DecryptAesV1(api.Base64UrlDecode(encryptedData), treeKey); err == nil {
			err = json.Unmarshal(data, &m)
		}
	} else {
		err = api.NewKeeperError("Encrypted data is empty")
	}
	return
}

func newNodeEntity() *baseEntity[proto_enterprise.Node, Node] {
	return &baseEntity[proto_enterprise.Node, Node]{
		baseStorage[proto_enterprise.Node, Node, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Node, treeKey []byte) *Node {
				var name string
				var m map[string]interface{}
				var er1 error
				if m, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
					name, _ = m["displayname"].(string)
				}
				if er1 != nil {
					api.GetLogger().Debug("Parse Node encrypted data", zap.Error(er1),
						zap.Int64("nodeId", protoEntity.NodeId))
				}
				return &Node{
					NodeId:               protoEntity.NodeId,
					Name:                 name,
					ParentId:             protoEntity.ParentId,
					BridgeId:             protoEntity.BridgeId,
					ScimId:               protoEntity.ScimId,
					LicenseId:            protoEntity.LicenseId,
					DuoEnabled:           protoEntity.DuoEnabled,
					RsaEnabled:           protoEntity.RsaEnabled,
					SsoServiceProviderId: protoEntity.SsoServiceProviderIds[:],
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.Node) int64 {
				return protoEntity.NodeId
			},
		},
	}
}

func newRoleEntity() IEnterpriseEntity[Role] {
	return &baseEntity[proto_enterprise.Role, Role]{
		baseStorage[proto_enterprise.Role, Role, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Role, treeKey []byte) *Role {
				var name string
				var m map[string]interface{}
				var er1 error
				if m, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
					name, _ = m["displayname"].(string)
				}
				if er1 != nil {
					api.GetLogger().Debug("Parse Role encrypted data", zap.Error(er1),
						zap.Int64("roleId", protoEntity.RoleId))
				}
				if len(name) == 0 {
					name = strconv.FormatInt(protoEntity.NodeId, 10)
				}
				return &Role{
					RoleId:         protoEntity.RoleId,
					Name:           name,
					NodeId:         protoEntity.NodeId,
					KeyType:        protoEntity.KeyType,
					VisibleBelow:   protoEntity.VisibleBelow,
					NewUserInherit: protoEntity.NewUserInherit,
					RoleType:       protoEntity.RoleType,
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.Role) int64 {
				return protoEntity.NodeId
			},
		},
	}
}

func newUserEntity() IEnterpriseEntity[User] {
	return &baseEntity[proto_enterprise.User, User]{
		baseStorage[proto_enterprise.User, User, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.User, treeKey []byte) *User {
				var u = &User{
					EnterpriseUserId:         protoEntity.EnterpriseUserId,
					Username:                 protoEntity.Username,
					FullName:                 protoEntity.FullName,
					JobTitle:                 protoEntity.JobTitle,
					NodeId:                   protoEntity.NodeId,
					Status:                   protoEntity.Status,
					Lock:                     protoEntity.Lock,
					UserId:                   protoEntity.UserId,
					AccountShareExpiration:   protoEntity.AccountShareExpiration,
					TfaEnabled:               protoEntity.TfaEnabled,
					TransferAcceptanceStatus: int32(protoEntity.TransferAcceptanceStatus),
				}
				if len(protoEntity.EncryptedData) > 0 {
					if strings.EqualFold(protoEntity.KeyType, "no_key") {
						u.FullName = protoEntity.EncryptedData
					} else {
						var m map[string]interface{}
						var er1 error
						var name string
						if m, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
							name, _ = m["displayname"].(string)
							if len(name) > 0 {
								u.FullName = name
							}
						}
						if er1 != nil {
							api.GetLogger().Debug("Parse User encrypted data", zap.Error(er1),
								zap.Int64("userId", protoEntity.EnterpriseUserId))
						}
					}
				}
				return u
			},
			onEntityKey: func(protoEntity *proto_enterprise.User) int64 {
				return protoEntity.EnterpriseUserId
			},
		},
	}
}

func newTeamEntity() IEnterpriseEntity[Team] {
	return &baseEntity[proto_enterprise.Team, Team]{
		baseStorage[proto_enterprise.Team, Team, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Team, treeKey []byte) *Team {
				var u = &Team{
					TeamUid:          protoEntity.TeamUid,
					Name:             protoEntity.Name,
					NodeId:           protoEntity.NodeId,
					RestrictEdit:     protoEntity.RestrictEdit,
					RestrictShare:    protoEntity.RestrictShare,
					RestrictView:     protoEntity.RestrictView,
					EncryptedTeamKey: api.Base64UrlDecode(protoEntity.EncryptedTeamKey),
				}
				if len(protoEntity.EncryptedData) > 0 {
					var er1 error
					if _, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
					}
					if er1 != nil {
						api.GetLogger().Debug("Parse Team encrypted data", zap.Error(er1),
							zap.String("teamUid", api.Base64UrlEncode(protoEntity.TeamUid)))
					}
				}

				return u
			},
			onEntityKey: func(protoEntity *proto_enterprise.Team) int64 {
				return getBytesHash(protoEntity.TeamUid)
			},
		},
	}
}

type baseLink[TP any, TK any] struct {
	baseStorage[TP, TK, [2]int64]
}

func (bl *baseLink[TP, TK]) CascadeDelete(id int64) {
	if bl.data == nil {
		return
	}
	var keys [][2]int64
	for k := range bl.data {
		if k[0] == id || k[1] == id {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		delete(bl.data, k)
	}
}

func newTeamUserEntity() IEnterpriseLink[TeamUser] {
	return &baseLink[proto_enterprise.TeamUser, TeamUser]{
		baseStorage[proto_enterprise.TeamUser, TeamUser, [2]int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.TeamUser, treeKey []byte) *TeamUser {
				return &TeamUser{
					TeamUid:          protoEntity.TeamUid,
					EnterpriseUserId: protoEntity.EnterpriseUserId,
					UserType:         protoEntity.UserType,
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.TeamUser) (key [2]int64) {
				key[0] = getBytesHash(protoEntity.TeamUid)
				key[1] = protoEntity.EnterpriseUserId
				return
			},
		},
	}
}
