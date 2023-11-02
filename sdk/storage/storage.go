package storage

type IUid interface {
	Uid() string
}

type IUidLink interface {
	SubjectUid() string
	ObjectUid() string
}

type IEntityStorage[T IUid] interface {
	GetEntity(string) (T, error)
	PutEntities([]T) error
	GetAll(func(T) bool) error
	DeleteUids([]string) error
}

type ILinkStorage[T IUidLink] interface {
	PutLinks([]T) error
	DeleteLinks([]IUidLink) error
	DeleteLinksForSubjects([]string) error
	DeleteLinksForObjects([]string) error
	GetLinksForSubjects([]string, func(T) bool) error
	GetLinksForObjects([]string, func(T) bool) error
	GetAll(func(T) bool) error
}

type uidLink struct {
	subjectUid string
	objectUid  string
}

func NewUidLink(subjectUid string, objectUid string) IUidLink {
	return &uidLink{
		subjectUid: subjectUid,
		objectUid:  objectUid,
	}
}

func (link *uidLink) SubjectUid() string {
	return link.subjectUid
}
func (link *uidLink) ObjectUid() string {
	return link.objectUid
}
