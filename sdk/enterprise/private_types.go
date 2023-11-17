package enterprise

import (
	"slices"
	"strings"
)

type node struct {
	nodeId               int64
	name                 string
	parentId             int64
	bridgeId             int64
	scimId               int64
	licenseId            int64
	duoEnabled           bool
	rsaEnabled           bool
	restrictVisibility   bool
	ssoServiceProviderId []int64
	encryptedData        string
}

func (n *node) NodeId() int64 {
	return n.nodeId
}
func (n *node) Name() string {
	return n.name
}
func (n *node) ParentId() int64 {
	return n.parentId
}
func (n *node) BridgeId() int64 {
	return n.bridgeId
}
func (n *node) ScimId() int64 {
	return n.scimId
}
func (n *node) LicenseId() int64 {
	return n.licenseId
}
func (n *node) DuoEnabled() bool {
	return n.duoEnabled
}
func (n *node) RsaEnabled() bool {
	return n.rsaEnabled
}
func (n *node) RestrictVisibility() bool {
	return n.restrictVisibility
}
func (n *node) SsoServiceProviderId() []int64 {
	return n.ssoServiceProviderId
}
func (n *node) EncryptedData() string {
	return n.encryptedData
}
func (n *node) SetName(name string) {
	n.name = name
}
func (n *node) SetParentId(parentId int64) {
	n.parentId = parentId
}
func (n *node) SetRestrictVisibility(restrictVisibility bool) {
	n.restrictVisibility = restrictVisibility
}

type role struct {
	roleId         int64
	name           string
	nodeId         int64
	keyType        string
	visibleBelow   bool
	newUserInherit bool
	roleType       string
	encryptedData  string
}

func (r *role) RoleId() int64 {
	return r.roleId
}
func (r *role) Name() string {
	return r.name
}
func (r *role) NodeId() int64 {
	return r.nodeId
}
func (r *role) KeyType() string {
	return r.keyType
}
func (r *role) VisibleBelow() bool {
	return r.visibleBelow
}
func (r *role) NewUserInherit() bool {
	return r.newUserInherit
}
func (r *role) RoleType() string {
	return r.roleType
}
func (r *role) EncryptedData() string {
	return r.encryptedData
}
func (r *role) SetName(name string) {
	r.name = name
}
func (r *role) SetNodeId(nodeId int64) {
	r.nodeId = nodeId
}
func (r *role) SetKeyType(keyType string) {
	r.keyType = keyType
}
func (r *role) SetVisibleBelow(visibleBelow bool) {
	r.visibleBelow = visibleBelow
}
func (r *role) SetNewUserInherit(newUserInherit bool) {
	r.newUserInherit = newUserInherit
}

type user struct {
	enterpriseUserId         int64
	username                 string
	fullName                 string
	jobTitle                 string
	nodeId                   int64
	status                   string
	lock                     int32
	userId                   int32
	accountShareExpiration   int64
	tfaEnabled               bool
	transferAcceptanceStatus int32
}

func (u *user) EnterpriseUserId() int64 {
	return u.enterpriseUserId
}
func (u *user) Username() string {
	return u.username
}
func (u *user) FullName() string {
	return u.fullName
}
func (u *user) JobTitle() string {
	return u.jobTitle
}
func (u *user) NodeId() int64 {
	return u.nodeId
}
func (u *user) Status() string {
	return u.status
}
func (u *user) Lock() int32 {
	return u.lock
}
func (u *user) UserId() int32 {
	return u.userId
}
func (u *user) AccountShareExpiration() int64 {
	return u.accountShareExpiration
}
func (u *user) TfaEnabled() bool {
	return u.tfaEnabled
}
func (u *user) TransferAcceptanceStatus() int32 {
	return u.transferAcceptanceStatus
}

type team struct {
	teamUid          string
	name             string
	nodeId           int64
	restrictEdit     bool
	restrictShare    bool
	restrictView     bool
	encryptedTeamKey []byte
}

func (t *team) TeamUid() string {
	return t.teamUid
}
func (t *team) Name() string {
	return t.name
}
func (t *team) NodeId() int64 {
	return t.nodeId
}
func (t *team) RestrictEdit() bool {
	return t.restrictEdit
}
func (t *team) RestrictShare() bool {
	return t.restrictShare
}
func (t *team) RestrictView() bool {
	return t.restrictView
}
func (t *team) EncryptedTeamKey() []byte {
	return t.encryptedTeamKey
}
func (t *team) SetName(name string) {
	t.name = name
}
func (t *team) SetNodeId(nodeId int64) {
	t.nodeId = nodeId
}
func (t *team) SetRestrictEdit(restrictEdit bool) {
	t.restrictEdit = restrictEdit
}
func (t *team) SetRestrictShare(restrictShare bool) {
	t.restrictShare = restrictShare
}
func (t *team) SetRestrictView(restrictView bool) {
	t.restrictView = restrictView
}

type teamUser struct {
	teamUid          string
	enterpriseUserId int64
	userType         string
}

func (tu *teamUser) TeamUid() string {
	return tu.teamUid
}
func (tu *teamUser) EnterpriseUserId() int64 {
	return tu.enterpriseUserId
}
func (tu *teamUser) UserType() string {
	return tu.userType
}

type roleUser struct {
	roleId           int64
	enterpriseUserId int64
}

func (ru *roleUser) RoleId() int64 {
	return ru.roleId
}
func (ru *roleUser) EnterpriseUserId() int64 {
	return ru.roleId
}

type managedNode struct {
	roleId                int64
	managedNodeId         int64
	cascadeNodeManagement bool
}

func (mn *managedNode) RoleId() int64 {
	return mn.roleId
}
func (mn *managedNode) ManagedNodeId() int64 {
	return mn.managedNodeId
}
func (mn *managedNode) CascadeNodeManagement() bool {
	return mn.cascadeNodeManagement
}

type rolePrivilege struct {
	roleId        int64
	managedNodeId int64
	privileges    []string
}

func (rp *rolePrivilege) RoleId() int64 {
	return rp.roleId
}
func (rp *rolePrivilege) ManagedNodeId() int64 {
	return rp.managedNodeId
}
func (rp *rolePrivilege) Privileges() []string {
	return rp.privileges
}
func (rp *rolePrivilege) SetPrivilege(privilege string) {
	privilege = strings.ToUpper(privilege)
	var idx = slices.IndexFunc(rp.privileges, func(p string) bool {
		return strings.Compare(strings.ToUpper(p), privilege) == 0
	})
	if idx < 0 {
		rp.privileges = append(rp.privileges, privilege)
	}
}
func (rp *rolePrivilege) RemovePrivilege(privilege string) {
	privilege = strings.ToUpper(privilege)
	var idx = slices.IndexFunc(rp.privileges, func(p string) bool {
		return strings.Compare(strings.ToUpper(p), privilege) == 0
	})
	if idx > 0 {
		rp.privileges = append(rp.privileges[:idx], rp.privileges[idx+1:]...)
	}
}

type roleEnforcement struct {
	roleId       int64
	enforcements map[string]string
}

func (re *roleEnforcement) RoleId() int64 {
	return re.roleId
}
func (re *roleEnforcement) Enforcements() map[string]string {
	return re.enforcements
}
