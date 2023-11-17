package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_enterprise"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"slices"
	"strconv"
	"strings"
)

type baseStorage[TP any, TK interface{}, K comparable] struct {
	data            map[K]TK
	onConvertEntity func(*TP, []byte) TK
	onEntityKey     func(*TP) K
	onStorageKey    func(*TP) string
}

func (bs *baseStorage[TP, TK, K]) clear() {
	bs.data = nil
}

func (bs *baseStorage[TP, TK, K]) newEntity(data []byte) (entity *TP, err error) {
	var protoEntity = new(TP)
	var ok bool
	var m proto.Message
	if m, ok = any(protoEntity).(proto.Message); ok {
		if err = proto.Unmarshal(data, m); err == nil {
			entity = protoEntity
		}
	} else {
		err = api.NewKeeperError("Invalid proto message class")
	}
	return
}

func (bs *baseStorage[TP, TK, K]) store(data []byte, encryptionKey []byte) (primaryKey string, err error) {
	var protoEntity *TP

	if protoEntity, err = bs.newEntity(data); err != nil {
		return
	}
	if bs.data == nil {
		bs.data = make(map[K]TK)
	}
	primaryKey = bs.getStorageKey(protoEntity)
	var keeperEntity = bs.toKeeper(protoEntity, encryptionKey)
	var key = bs.getKey(protoEntity)
	bs.data[key] = keeperEntity
	return
}
func (bs *baseStorage[TP, TK, K]) delete(data []byte) (primaryKey string, err error) {
	var protoEntity *TP
	if protoEntity, err = bs.newEntity(data); err != nil {
		return
	}
	primaryKey = bs.getStorageKey(protoEntity)
	if bs.data == nil {
		return
	}
	var key = bs.getKey(protoEntity)
	delete(bs.data, key)
	return
}

func (bs *baseStorage[TP, TK, K]) toKeeper(protoEntity *TP, treeKey []byte) TK {
	if bs.onConvertEntity != nil {
		return bs.onConvertEntity(protoEntity, treeKey)
	} else {
		panic("Not implemented")
	}
}

func (bs *baseStorage[TP, TK, K]) getKey(protoEntity *TP) (key K) {
	if bs.onEntityKey != nil {
		return bs.onEntityKey(protoEntity)
	}
	panic("Not implemented")
}

func (bs *baseStorage[TP, TK, K]) getStorageKey(protoEntity *TP) (primaryKey string) {
	if bs.onStorageKey != nil {
		return bs.onStorageKey(protoEntity)
	}
	panic("Not implemented")
}

func (bs *baseStorage[TP, TK, K]) enumerateData(cmp func(K) bool, cb func(TK) bool) {
	if bs.data != nil {
		for k, v := range bs.data {
			if !cmp(k) {
				continue
			}
			if !cb(v) {
				break
			}
		}
	}
}
func (bs *baseStorage[TP, TK, K]) getData(key K) (result TK) {
	result, _ = bs.data[key]
	return
}

type baseEntity[TP any, TK interface{}, K storage.Key] struct {
	baseStorage[TP, TK, K]
}

func (bs *baseEntity[TP, TK, K]) GetEntity(key K) (result TK) {
	result = bs.getData(key)
	return
}

func (bs *baseEntity[TP, TK, K]) GetAllEntities(cb func(TK) bool) {
	bs.enumerateData(
		func(_ K) bool { return true },
		func(entity TK) bool { return cb(entity) })
}

type iNodeEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[INode, int64]
}

type iRoleEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[IRole, int64]
}

type iUserEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[IUser, int64]
}

type iTeamEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[ITeam, string]
}

type iTeamUserLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[string, int64]
	IEnterpriseLink[ITeamUser, string, int64]
}

type iRoleUserLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, int64]
	IEnterpriseLink[IRoleUser, int64, int64]
}
type iRolePrivilegeLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, int64]
	IEnterpriseLink[IRolePrivilege, int64, int64]
}

func newNodeEntity() iNodeEntity {
	return &baseEntity[proto_enterprise.Node, INode, int64]{
		baseStorage[proto_enterprise.Node, INode, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Node, treeKey []byte) INode {
				var name string
				var encData *EncryptedData
				var er1 error
				if encData, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
					name = encData.DisplayName
				} else {
					api.GetLogger().Debug("Parse Node encrypted data", zap.Error(er1),
						zap.Int64("nodeId", protoEntity.NodeId))
				}
				if len(name) == 0 {
					name = strconv.FormatInt(protoEntity.NodeId, 16)
				}
				return &node{
					nodeId:               protoEntity.NodeId,
					name:                 name,
					parentId:             protoEntity.ParentId,
					bridgeId:             protoEntity.BridgeId,
					scimId:               protoEntity.ScimId,
					licenseId:            protoEntity.LicenseId,
					duoEnabled:           protoEntity.DuoEnabled,
					rsaEnabled:           protoEntity.RsaEnabled,
					ssoServiceProviderId: protoEntity.SsoServiceProviderIds[:],
					encryptedData:        protoEntity.GetEncryptedData(),
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.Node) int64 {
				return protoEntity.NodeId
			},
			onStorageKey: func(protoEntity *proto_enterprise.Node) string {
				return strconv.FormatInt(protoEntity.NodeId, 16)
			},
		},
	}
}

func newRoleEntity() iRoleEntity {
	return &baseEntity[proto_enterprise.Role, IRole, int64]{
		baseStorage[proto_enterprise.Role, IRole, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Role, treeKey []byte) IRole {
				var name string
				var encData *EncryptedData
				var er1 error
				if encData, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
					name = encData.DisplayName
				} else {
					api.GetLogger().Debug("Parse Role encrypted data", zap.Error(er1),
						zap.Int64("roleId", protoEntity.RoleId))
				}
				if len(name) == 0 {
					name = strconv.FormatInt(protoEntity.RoleId, 16)
				}
				return &role{
					roleId:         protoEntity.RoleId,
					name:           name,
					nodeId:         protoEntity.NodeId,
					keyType:        protoEntity.KeyType,
					visibleBelow:   protoEntity.VisibleBelow,
					newUserInherit: protoEntity.NewUserInherit,
					roleType:       protoEntity.RoleType,
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.Role) int64 {
				return protoEntity.RoleId
			},
			onStorageKey: func(protoEntity *proto_enterprise.Role) string {
				return strconv.FormatInt(protoEntity.RoleId, 16)
			},
		},
	}
}

func newUserEntity() iUserEntity {
	return &baseEntity[proto_enterprise.User, IUser, int64]{
		baseStorage[proto_enterprise.User, IUser, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.User, treeKey []byte) IUser {
				var u = &user{
					enterpriseUserId:         protoEntity.EnterpriseUserId,
					username:                 protoEntity.Username,
					fullName:                 protoEntity.FullName,
					jobTitle:                 protoEntity.JobTitle,
					nodeId:                   protoEntity.NodeId,
					status:                   protoEntity.Status,
					lock:                     protoEntity.Lock,
					userId:                   protoEntity.UserId,
					accountShareExpiration:   protoEntity.AccountShareExpiration,
					tfaEnabled:               protoEntity.TfaEnabled,
					transferAcceptanceStatus: int32(protoEntity.TransferAcceptanceStatus),
				}
				if len(protoEntity.EncryptedData) > 0 {
					if strings.EqualFold(protoEntity.KeyType, "no_key") {
						u.fullName = protoEntity.EncryptedData
					} else {
						var encData *EncryptedData
						var er1 error
						var name string
						if encData, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
							name = encData.DisplayName
							if len(name) > 0 {
								u.fullName = name
							}
						} else {
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
			onStorageKey: func(protoEntity *proto_enterprise.User) string {
				return strconv.FormatInt(protoEntity.EnterpriseUserId, 16)
			},
		},
	}
}

func newTeamEntity() iTeamEntity {
	return &baseEntity[proto_enterprise.Team, ITeam, string]{
		baseStorage[proto_enterprise.Team, ITeam, string]{
			onConvertEntity: func(protoEntity *proto_enterprise.Team, treeKey []byte) ITeam {
				var u = &team{
					teamUid:          api.Base64UrlEncode(protoEntity.TeamUid),
					name:             protoEntity.Name,
					nodeId:           protoEntity.NodeId,
					restrictEdit:     protoEntity.RestrictEdit,
					restrictShare:    protoEntity.RestrictShare,
					restrictView:     protoEntity.RestrictView,
					encryptedTeamKey: api.Base64UrlDecode(protoEntity.EncryptedTeamKey),
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
			onEntityKey: func(protoEntity *proto_enterprise.Team) string {
				return api.Base64UrlEncode(protoEntity.TeamUid)
			},
			onStorageKey: func(protoEntity *proto_enterprise.Team) string {
				return api.Base64UrlEncode(protoEntity.TeamUid)
			},
		},
	}
}

type LinkKey[KS comparable, KO comparable] struct {
	V1 KS
	V2 KO
}

type baseLink[TP any, TK interface{}, KS comparable, KO comparable] struct {
	baseStorage[TP, TK, LinkKey[KS, KO]]
}

func (bl *baseLink[TP, TK, KS, KO]) cascadeDeleteSubject(subjectId KS) {
	if bl.data == nil {
		return
	}
	var keys []LinkKey[KS, KO]
	for k := range bl.data {
		if k.V1 == subjectId {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		delete(bl.data, k)
	}
}
func (bl *baseLink[TP, TK, KS, KO]) cascadeDeleteObject(objectId KO) {
	if bl.data == nil {
		return
	}
	var keys []LinkKey[KS, KO]
	for k := range bl.data {
		if k.V2 == objectId {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		delete(bl.data, k)
	}
}

func (bl *baseLink[TP, TK, KS, KO]) GetLinksBySubject(subjectId KS, cb func(TK) bool) {
	bl.enumerateData(
		func(l LinkKey[KS, KO]) bool { return l.V1 == subjectId },
		func(link TK) bool { return cb(link) })
}
func (bl *baseLink[TP, TK, KS, KO]) GetLinksByObject(objectId KO, cb func(TK) bool) {
	bl.enumerateData(
		func(l LinkKey[KS, KO]) bool { return l.V2 == objectId },
		func(link TK) bool { return cb(link) })
}
func (bl *baseLink[TP, TK, KS, KO]) GetAllLinks(cb func(TK) bool) {
	bl.enumerateData(
		func(l LinkKey[KS, KO]) bool { return true },
		func(link TK) bool { return cb(link) })
}
func (bl *baseLink[TP, TK, KS, KO]) GetLink(subjectId KS, objectId KO) (result TK) {
	result, _ = bl.data[LinkKey[KS, KO]{
		V1: subjectId,
		V2: objectId,
	}]
	return
}

func newTeamUserLink() iTeamUserLink {
	return &baseLink[proto_enterprise.TeamUser, ITeamUser, string, int64]{
		baseStorage[proto_enterprise.TeamUser, ITeamUser, LinkKey[string, int64]]{
			onConvertEntity: func(protoEntity *proto_enterprise.TeamUser, treeKey []byte) ITeamUser {
				return &teamUser{
					teamUid:          api.Base64UrlEncode(protoEntity.TeamUid),
					enterpriseUserId: protoEntity.EnterpriseUserId,
					userType:         protoEntity.UserType,
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.TeamUser) (key LinkKey[string, int64]) {
				key.V1 = api.Base64UrlEncode(protoEntity.TeamUid)
				key.V2 = protoEntity.EnterpriseUserId
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.TeamUser) string {
				return strings.Join([]string{
					api.Base64UrlEncode(protoEntity.TeamUid),
					strconv.FormatInt(protoEntity.EnterpriseUserId, 16)}, "|")
			},
		},
	}
}

func newRoleUserLink() iRoleUserLink {
	return &baseLink[proto_enterprise.RoleUser, IRoleUser, int64, int64]{
		baseStorage[proto_enterprise.RoleUser, IRoleUser, LinkKey[int64, int64]]{
			onConvertEntity: func(protoEntity *proto_enterprise.RoleUser, treeKey []byte) IRoleUser {
				return &roleUser{
					roleId:           protoEntity.RoleId,
					enterpriseUserId: protoEntity.EnterpriseUserId,
				}
			},
			onEntityKey: func(protoEntity *proto_enterprise.RoleUser) (key LinkKey[int64, int64]) {
				key.V1 = protoEntity.RoleId
				key.V2 = protoEntity.EnterpriseUserId
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.RoleUser) string {
				return strings.Join([]string{
					strconv.FormatInt(protoEntity.RoleId, 16),
					strconv.FormatInt(protoEntity.EnterpriseUserId, 16)}, "|")
			},
		},
	}
}

type rolePrivilegeLink struct {
	data map[LinkKey[int64, int64]]map[string]bool
}

func (rpl *rolePrivilegeLink) newEntity(data []byte) (rolePrivilege *proto_enterprise.RolePrivilege, err error) {
	rolePrivilege = new(proto_enterprise.RolePrivilege)
	var ok bool
	var m proto.Message
	if m, ok = any(rolePrivilege).(proto.Message); ok {
		err = proto.Unmarshal(data, m)
	} else {
		err = api.NewKeeperError("Invalid proto message class")
	}
	return
}

func (rpl *rolePrivilegeLink) store(data []byte, _ []byte) (primaryKey string, err error) {
	var rp *proto_enterprise.RolePrivilege
	if rp, err = rpl.newEntity(data); err != nil {
		return
	}
	if rpl.data == nil {
		rpl.data = make(map[LinkKey[int64, int64]]map[string]bool)
	}
	var lk = LinkKey[int64, int64]{
		V1: rp.RoleId,
		V2: rp.ManagedNodeId,
	}
	var ok bool
	var enforcements map[string]bool
	if enforcements, ok = rpl.data[lk]; !ok {
		enforcements = make(map[string]bool)
		rpl.data[lk] = enforcements
	}
	enforcements[rp.GetPrivilegeType()] = true
	primaryKey = fmt.Sprintf("%s|%s|%s", strconv.FormatInt(rp.RoleId, 10), strconv.FormatInt(rp.ManagedNodeId, 10), rp.GetPrivilegeType())
	return
}
func (rpl *rolePrivilegeLink) delete(data []byte) (primaryKey string, err error) {
	var rp *proto_enterprise.RolePrivilege
	if rp, err = rpl.newEntity(data); err != nil {
		return
	}
	if rpl.data != nil {
		var lk = LinkKey[int64, int64]{
			V1: rp.RoleId,
			V2: rp.ManagedNodeId,
		}
		var ok bool
		var enforcements map[string]bool
		if enforcements, ok = rpl.data[lk]; ok {
			delete(enforcements, rp.GetPrivilegeType())
		}
	}
	primaryKey = fmt.Sprintf("%s|%s|%s", strconv.FormatInt(rp.RoleId, 10), strconv.FormatInt(rp.ManagedNodeId, 10), rp.GetPrivilegeType())
	return
}
func (rpl *rolePrivilegeLink) clear() {
	rpl.data = nil
}
func (rpl *rolePrivilegeLink) enumerateData(cmp func(key LinkKey[int64, int64]) bool, cb func(IRolePrivilege) bool) {
	if rpl.data == nil {
		return
	}
	for k, v := range rpl.data {
		if !cmp(k) {
			continue
		}
		var rp = &rolePrivilege{
			roleId:        k.V1,
			managedNodeId: k.V2,
		}
		for e := range v {
			rp.privileges = append(rp.privileges, e)
		}
		if len(rp.privileges) > 1 {
			slices.Sort(rp.privileges)
		}
		if cb != nil {
			if !cb(rp) {
				break
			}
		}
	}
}

func (rpl *rolePrivilegeLink) GetAllLinks(cb func(IRolePrivilege) bool) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return true },
		func(privilege IRolePrivilege) bool { return cb(privilege) })
}
func (rpl *rolePrivilegeLink) GetLink(roleId int64, nodeId int64) (result IRolePrivilege) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return key.V1 == roleId && key.V2 == nodeId },
		func(privilege IRolePrivilege) bool {
			result = privilege
			return false
		})
	return
}
func (rpl *rolePrivilegeLink) GetLinksBySubject(roleId int64, cb func(IRolePrivilege) bool) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return key.V1 == roleId },
		func(privilege IRolePrivilege) bool { return cb(privilege) })
}

func (rpl *rolePrivilegeLink) GetLinksByObject(nodeId int64, cb func(IRolePrivilege) bool) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return key.V2 == nodeId },
		func(privilege IRolePrivilege) bool { return cb(privilege) })
}
func (rpl *rolePrivilegeLink) cascadeDeleteSubject(roleId int64) {
	if rpl.data == nil {
		return
	}
	if rpl.data != nil {
		var links []LinkKey[int64, int64]
		for k := range rpl.data {
			if k.V1 == roleId {
				links = append(links, k)
			}
		}
		for _, k := range links {
			delete(rpl.data, k)
		}
	}
}
func (rpl *rolePrivilegeLink) cascadeDeleteObject(nodeId int64) {
	if rpl.data == nil {
		return
	}
	if rpl.data != nil {
		var links []LinkKey[int64, int64]
		for k := range rpl.data {
			if k.V2 == nodeId {
				links = append(links, k)
			}
		}
		for _, k := range links {
			delete(rpl.data, k)
		}
	}
}

func newRolePrivileges() iRolePrivilegeLink {
	return new(rolePrivilegeLink)
}

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

type iEnterprisePlugin interface {
	store(data []byte, encryptionKey []byte) (primaryKey string, err error)
	delete(data []byte) (primaryKey string, err error)
	clear()
}
type iEnterpriseLinkPlugin[KS storage.Key, KO storage.Key] interface {
	cascadeDeleteSubject(KS)
	cascadeDeleteObject(KO)
}

type enterpriseData struct {
	enterpriseInfo *enterpriseInfo
	nodes          iNodeEntity
	roles          iRoleEntity
	users          iUserEntity
	teams          iTeamEntity
	teamUsers      iTeamUserLink
	roleUsers      iRoleUserLink
	rolePrivileges iRolePrivilegeLink
	rootNode       INode
}

func (ed *enterpriseData) GetRootNode() INode {
	return ed.rootNode
}

func (ed *enterpriseData) EnterpriseInfo() IEnterpriseInfo {
	return ed.enterpriseInfo
}

func (ed *enterpriseData) getSupportedEntities() (res []proto_enterprise.EnterpriseDataEntity) {
	res = append(res, proto_enterprise.EnterpriseDataEntity_NODES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_TEAMS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_TEAM_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLE_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLE_PRIVILEGES)
	return
}

func (ed *enterpriseData) getEnterprisePlugin(entityType proto_enterprise.EnterpriseDataEntity) (plugin iEnterprisePlugin) {
	switch entityType {
	case proto_enterprise.EnterpriseDataEntity_NODES:
		return ed.nodes
	case proto_enterprise.EnterpriseDataEntity_ROLES:
		return ed.roles
	case proto_enterprise.EnterpriseDataEntity_USERS:
		return ed.users
	case proto_enterprise.EnterpriseDataEntity_TEAMS:
		return ed.teams
	case proto_enterprise.EnterpriseDataEntity_TEAM_USERS:
		return ed.teamUsers
	case proto_enterprise.EnterpriseDataEntity_ROLE_USERS:
		return ed.roleUsers
	case proto_enterprise.EnterpriseDataEntity_ROLE_PRIVILEGES:
		return ed.rolePrivileges
	}
	api.GetLogger().Debug("Enterprise entity is not supported.", zap.String("entity", entityType.String()))
	return
}

func (ed *enterpriseData) Nodes() IEnterpriseEntity[INode, int64] {
	return ed.nodes
}
func (ed *enterpriseData) Roles() IEnterpriseEntity[IRole, int64] {
	return ed.roles
}
func (ed *enterpriseData) Users() IEnterpriseEntity[IUser, int64] {
	return ed.users
}
func (ed *enterpriseData) Teams() IEnterpriseEntity[ITeam, string] {
	return ed.teams
}
func (ed *enterpriseData) TeamUsers() IEnterpriseLink[ITeamUser, string, int64] {
	return ed.teamUsers
}
func (ed *enterpriseData) RoleUsers() IEnterpriseLink[IRoleUser, int64, int64] {
	return ed.roleUsers
}
func (ed *enterpriseData) RolePrivileges() IEnterpriseLink[IRolePrivilege, int64, int64] {
	return ed.rolePrivileges
}

func newEnterpriseData(ei *enterpriseInfo) *enterpriseData {
	var ed = &enterpriseData{
		enterpriseInfo: ei,
		nodes:          newNodeEntity(),
		roles:          newRoleEntity(),
		users:          newUserEntity(),
		teams:          newTeamEntity(),
		teamUsers:      newTeamUserLink(),
		roleUsers:      newRoleUserLink(),
		rolePrivileges: newRolePrivileges(),
	}

	return ed
}
