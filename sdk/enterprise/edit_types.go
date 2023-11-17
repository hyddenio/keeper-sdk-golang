package enterprise

func NewNode(nodeId int64) INodeEdit {
	return &node{
		nodeId: nodeId,
	}
}

func CloneNode(n INode) INodeEdit {
	return &node{
		nodeId:               n.NodeId(),
		name:                 n.Name(),
		parentId:             n.ParentId(),
		bridgeId:             n.BridgeId(),
		scimId:               n.ScimId(),
		licenseId:            n.LicenseId(),
		duoEnabled:           n.DuoEnabled(),
		rsaEnabled:           n.RsaEnabled(),
		restrictVisibility:   n.RestrictVisibility(),
		ssoServiceProviderId: n.SsoServiceProviderId(),
		encryptedData:        n.EncryptedData(),
	}
}

func NewRole(roleId int64) IRoleEdit {
	return &role{
		roleId: roleId,
	}
}
func CloneRole(r IRole) IRoleEdit {
	return &role{
		roleId:         r.RoleId(),
		name:           r.Name(),
		nodeId:         r.NodeId(),
		keyType:        r.KeyType(),
		visibleBelow:   r.VisibleBelow(),
		newUserInherit: r.NewUserInherit(),
		roleType:       r.RoleType(),
		encryptedData:  r.EncryptedData(),
	}
}

func NewTeam(teamUid string) ITeamEdit {
	return &team{
		teamUid: teamUid,
	}
}
func CloneTeam(t ITeam) ITeamEdit {
	return &team{
		teamUid:          t.TeamUid(),
		name:             t.Name(),
		nodeId:           t.NodeId(),
		restrictEdit:     t.RestrictEdit(),
		restrictShare:    t.RestrictShare(),
		restrictView:     t.RestrictView(),
		encryptedTeamKey: t.EncryptedTeamKey(),
	}
}
