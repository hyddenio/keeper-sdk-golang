package vault

import (
  "crypto"
	"encoding/json"

	"keepersecurity.com/sdk/auth"
)

type CustomField struct {
	Name string
	Value string
	Type string
}

type AttachmentFileThumb struct {
	Id string
	Type string
	Size int32
}

type AttachmentFile struct {
	Id string
	Name string
	Title string
	Type string
	Size int32
	Key []byte
	Thumbnails []*AttachmentFileThumb
}

type ExtraField struct {
	Id string
	FieldType string
	FieldTitle string
	Extra map[string]interface{}
}

type customField struct {
	Name string 			`json:"name"`
	Value string 			`json:"value"`
	Type string				`json:"type"`
}
type recordData struct {
	Title string          `json:"title"`
	Secret1 string        `json:"secret1"`
	Secret2 string        `json:"secret2"`
	Link string           `json:"link"`
	Notes string          `json:"notes"`
	Custom []*customField `json:"custom"`
}

type PasswordRecord struct {
	RecordUid string
	Title string
	Login string
	Password string
	Link string
	Notes string
	customFields []*CustomField
	Attachments []*AttachmentFile
	ExtraFields []*ExtraField
	owner bool
	shared bool
	recordKey []byte
}
func NewPasswordRecordFromStorage(sr IStorageRecord, key []byte) (record *PasswordRecord, err error) {
	record = &PasswordRecord{
		RecordUid:    sr.RecordUid(),
		owner:        sr.Owner(),
		shared:       sr.Shared(),
		recordKey:    key,
		customFields: make([]*CustomField, 0, 10),
		Attachments:  make([]*AttachmentFile, 0, 10),
		ExtraFields:  make([]*ExtraField, 0, 10),
	}
	var dataBytes []byte
	if dataBytes, err = auth.DecryptAesV1(auth.Base64UrlDecode(sr.Data()), key); err == nil {
		var rd = new(recordData)
		if err = json.Unmarshal(dataBytes, rd); err == nil {
			record.Title = rd.Title
			record.Login = rd.Secret1
			record.Password = rd.Secret2
			record.Link = rd.Link
			record.Notes = rd.Notes
			if rd.Custom != nil {
				for _, cr := range rd.Custom {
					record.customFields = append(record.customFields, &CustomField{
						Name:  cr.Name,
						Value: cr.Value,
						Type:  cr.Type,
					})
				}
			}
		}
	}
	if err != nil {
		return
	}
	if extra := sr.Extra(); extra != "" {
		var extraBytes []byte
		if extraBytes, err = auth.DecryptAesV1(auth.Base64UrlDecode(extra), key); err == nil {
			var extraMap = make(map[string]interface{})
			if err = json.Unmarshal(extraBytes, &extraMap); err == nil {
				if ifiles := extraMap["files"]; ifiles != nil {
					if afiles, ok := ifiles.([]interface{}); ok {
						for _, ifile := range afiles {
							if file, ok := ifile.(map[string]interface{}); ok {
								var af = new(AttachmentFile)
								for k, v := range file {
									switch k {
									case "id":
										af.Id, _ = v.(string)
									case "name":
										af.Name, _ = v.(string)
									case "title":
										af.Title, _ = v.(string)
									case "type":
										af.Type, _ = v.(string)
									case "key":
										if vk, ok := v.(string); ok {
											af.Key = auth.Base64UrlDecode(vk)
										}
									case "size":
										if f, ok := v.(float64); ok {
											af.Size = int32(f)
										}
									case "thumbnails":
										if thumbs, ok := v.([]map[string]interface{}); ok {
											af.Thumbnails = make([]*AttachmentFileThumb, 0)
											for _, thumb := range thumbs {
												var at = new(AttachmentFileThumb)
												for k, v = range thumb {
													switch k {
													case "id":
														at.Id, _ = v.(string)
													case "type":
														at.Type, _ = v.(string)
													case "size":
														at.Size, _ = v.(int32)
													}
												}
												af.Thumbnails = append(af.Thumbnails, at)
											}
										}
									}
								}
								record.Attachments = append(record.Attachments, af)
							}
						}
					}
				}

				if ifields := extraMap["fields"]; ifields != nil {
					if fields, ok := ifields.([]map[string]interface{}); ok {
						for _, field := range fields {
							ef := new(ExtraField)
							ef.Extra = make(map[string]interface{})
							for k, v := range field {
								switch k {
								case "id":
									ef.Id, _ = v.(string)
								case "field_type":
									ef.FieldType = v.(string)
								case "field_title":
									ef.FieldTitle = v.(string)
								default:
									ef.Extra[k] = v
								}
							}
							record.ExtraFields = append(record.ExtraFields, ef)
						}
					}
				}
			}
		}
	}
	return
}

func (p *PasswordRecord) Serialize(storage IStorageRecord) (data []byte, extra []byte, udata map[string]interface{}, err error) {
	rData := & recordData{
		Title:   p.Title,
		Secret1: p.Login,
		Secret2: p.Password,
		Link:    p.Link,
		Notes:   p.Notes,
		Custom:  make([]*customField, 0),
	}
	if p.customFields != nil {
		for _, c := range p.customFields {
			cf := &customField{
				Name: c.Name,
				Value: c.Value,
				Type:  c.Type,
			}
			rData.Custom = append(rData.Custom, cf)
		}
	}
	if data, err = json.Marshal(rData); err != nil {
		return
	}
	extraMap := make(map[string]interface{})
	if storage != nil {
		srcExtra := storage.Extra()
		if srcExtra !=  "" {
			if extra, err = auth.DecryptAesV1(auth.Base64UrlDecode(srcExtra), p.recordKey); err != nil {
				return
			}
			if err = json.Unmarshal(extra, &extraMap); err != nil {
				return
			}
		}
		delete(extraMap, "files")
		delete(extraMap, "fields")
	}
	if p.Attachments != nil {
		files := make([]map[string]interface{}, 0)
		for _, atta := range p.Attachments {
			file := make(map[string]interface{})
			file["id"] = atta.Id
			file["name"] = atta.Name
			file["title"] = atta.Title
			file["type"] = atta.Type
			file["size"] = atta.Size
			file["key"] = auth.Base64UrlEncode(atta.Key)
			if atta.Thumbnails != nil {
				thumbs := make([]map[string]interface{}, 0)
				for _, th := range atta.Thumbnails {
					thumb := make(map[string]interface{})
					thumb["id"] = th.Id
					thumb["type"] = th.Type
					thumb["size"] = th.Size
					thumbs = append(thumbs, thumb)
				}
				file["thumbnails"] = thumbs
			}
			files = append(files, file)
		}
		extraMap["files"] = files
	}
	if p.ExtraFields != nil {
		fields := make([]map[string]interface{}, 0)
		for _, ef := range p.ExtraFields {
			field := make(map[string]interface{})
			if ef.Extra != nil {
				for k, v := range ef.Extra {
					field[k] = v
				}
			}
			field["id"] = ef.Id
			field["field_type"] = ef.FieldType
			field["field_title"] = ef.FieldTitle
			fields = append(fields, field)
		}
		extraMap["fields"] = fields
	}
	if len(extraMap) > 0 {
		if extra, err = json.Marshal(&extraMap); err != nil {
			return
		}
	} else {
		extra = nil
	}

	if storage != nil && storage.UData() != "" {
		udata = make(map[string]interface{})
		if err1 := json.Unmarshal([]byte(storage.UData()), &udata); err1 == nil {
			if udata != nil {
				delete(udata, "file_ids")
			}
		}
	}
	if len(p.Attachments) > 0 {
		if udata == nil {
			udata = make(map[string]interface{})
		}
		files := make([]string, 0)
		for _, atta := range p.Attachments {
			files = append(files, atta.Id)
			if atta.Thumbnails != nil {
				for _, th := range atta.Thumbnails {
					files = append(files, th.Id)
				}
			}
		}
		udata["file_ids"] = files
	}
	return
}

func (p *PasswordRecord) Shared() bool {
	return p.shared
}
func (p *PasswordRecord) Owner() bool {
	return p.owner
}
func (p *PasswordRecord) RecordKey() []byte {
	return p.recordKey
}
func (p *PasswordRecord) CustomFields() []*CustomField {
	return p.customFields
}
func (p *PasswordRecord) GetCustomField(name string) *CustomField {
	if p.customFields != nil {
		for _, e := range p.customFields {
			if e.Name == name {
				return e
			}
		}
	}
	return nil
}
func (p *PasswordRecord) SetCustomField(name string, value string) {
	var field = p.GetCustomField(name)
	if field == nil {
		if p.customFields == nil {
			p.customFields = make([]*CustomField, 0)
		}
		p.customFields = append(p.customFields, & CustomField{
			Name:  name,
			Value: value,
		})
	} else {
		field.Value = value
	}
}
func (p *PasswordRecord) RemoveCustomField(name string) *CustomField {
	if p.customFields != nil {
		for i, e := range p.customFields {
			if e.Name == name {
				lastIndex := len(p.customFields) - 1
				if i < lastIndex {
					p.customFields[i] = p.customFields[lastIndex]
				}
				p.customFields = p.customFields[:lastIndex]
				return e
			}
		}
	}
	return nil
}

type SharedFolderUserPermission struct {
	UserId string
	UserType int32
	ManageRecords bool
	ManageUsers bool
}
type SharedFolderRecordPermission struct {
	RecordUid string
	CanShare bool
	CanEdit bool
}
type SharedFolder struct {
	SharedFolderUid      string
	Name                 string
	DefaultManageRecords bool
	DefaultManageUsers   bool
	DefaultCanEdit       bool
	DefaultCanShare      bool
	userPermissions      []*SharedFolderUserPermission
	recordPermissions    []*SharedFolderRecordPermission
	sharedFolderKey      []byte
}
func NewSharedFolderFromStorage(
	sf IStorageSharedFolder,
	sfup []IStorageSharedFolderPermission,
	sfrp []IStorageRecordKey,
	key []byte) (sharedFolder *SharedFolder) {

	sharedFolder = &SharedFolder{
		SharedFolderUid:      sf.SharedFolderUid(),
		DefaultManageRecords: sf.DefaultManageRecords(),
		DefaultManageUsers:   sf.DefaultManageUsers(),
		DefaultCanEdit:       sf.DefaultCanEdit(),
		DefaultCanShare:      sf.DefaultCanShare(),
		userPermissions:      make([]*SharedFolderUserPermission, 0),
		recordPermissions:    make([]*SharedFolderRecordPermission, 0),
		sharedFolderKey:      key,
	}
	if name, err := auth.DecryptAesV1(auth.Base64UrlDecode(sf.Name()), key); err == nil {
		sharedFolder.Name = string(name)
	} else {
		sharedFolder.Name = sharedFolder.SharedFolderUid
	}
	for _, up := range sfup {
		sharedFolder.userPermissions = append(sharedFolder.userPermissions, & SharedFolderUserPermission{
			UserId:        up.UserId(),
			UserType:      up.UserType(),
			ManageRecords: up.ManageRecords(),
			ManageUsers:   up.ManageUsers(),
		})
	}
	for _, rp := range sfrp {
		sharedFolder.recordPermissions = append(sharedFolder.recordPermissions, & SharedFolderRecordPermission{
			RecordUid: rp.RecordUid(),
			CanShare:  rp.CanShare(),
			CanEdit:   rp.CanEdit(),
		})
	}
	return
}

func (sf *SharedFolder) SharedFolderKey() []byte {
	return sf.sharedFolderKey
}
func (sf *SharedFolder) UserPermissions() []*SharedFolderUserPermission {
	return sf.userPermissions
}
func (sf *SharedFolder) RecordPermissions() []*SharedFolderRecordPermission {
	return sf.recordPermissions
}

type EnterpriseTeam struct {
	TeamUid string
	Name string
	RestrictEdit bool
	RestrictShare bool
	RestrictView bool

	teamKey []byte
	privateKey crypto.PrivateKey
}
func NewTeamFromStorage(st IStorageTeam, key []byte) (team *EnterpriseTeam, err error) {
	team = & EnterpriseTeam{
		TeamUid:       st.TeamUid(),
		Name:          st.Name(),
		RestrictEdit:  st.RestrictEdit(),
		RestrictShare: st.RestrictShare(),
		RestrictView:  st.RestrictView(),
		teamKey:       key,
		privateKey:    nil,
	}
	var pk []byte
	if pk, err = auth.DecryptAesV1(auth.Base64UrlDecode(st.TeamPrivateKey()), key); err == nil {
		team.privateKey, err = auth.LoadRsaPrivateKey(pk)
	}
	return
}
func (t *EnterpriseTeam) TeamKey() []byte {
	return t.teamKey
}
func (t *EnterpriseTeam) PrivateKey() crypto.PrivateKey {
	return t.teamKey
}


var empty = struct{}{}
type Set struct {
	_map map[string]struct{}
}
func (set *Set) Add(key string) {
	if set._map == nil {
		set._map = make(map[string]struct{})
	}
	set._map[key] = empty
}
func (set *Set) Remove(key string) {
	if set._map != nil {
		delete(set._map, key)
	}
}
func (set *Set) IsSet(key string) (ok bool) {
	if set._map != nil {
		_, ok = set._map[key]
	}
	return
}
func (set *Set) Keys() (result []string) {
	result = make([]string, len(set._map))
	if len(set._map) > 0 {
		i := 0
		for k := range set._map {
			result[i] = k
			i++
		}
	}
	return
}

type Folder struct {
	FolderUid       string
	FolderType      string
	Name            string
	ParentUid       string
	SharedFolderUid string
	subfolders      Set
	records         Set
}
func (f *Folder) Subfolders() Set {
	return f.subfolders
}
func (f *Folder) Records() Set {
	return f.records
}
