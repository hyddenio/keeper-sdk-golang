package storage

import (
	"encoding/binary"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"hash/crc64"
	"sync"
)

var (
	hasher = crc64.New(crc64.MakeTable(crc64.ISO))
	mutex  sync.Mutex
)

func getKey[K Key](key K) (res int64, err error) {
	var ok bool
	if res, ok = any(key).(int64); ok {
		return
	}
	mutex.Lock()
	hasher.Reset()
	switch v := any(key).(type) {
	case string:
		_, err = hasher.Write([]byte(v))
	case []byte:
		_, err = hasher.Write(v)
	default:
		err = api.NewKeeperError("Unsupported Key type")
	}
	if err == nil {
		res = int64(hasher.Sum64())
	}
	mutex.Unlock()
	return
}

type inMemoryEntityStorage[K Key, T IUid[K]] struct {
	storage map[int64]T
}

func NewInMemoryEntityStorage[K Key, T IUid[K]]() IEntityStorage[K, T] {
	return new(inMemoryEntityStorage[K, T])
}

func (mes *inMemoryEntityStorage[K, T]) GetEntity(uid K) (entity T, err error) {
	if mes.storage == nil {
		return
	}
	var keyHash int64
	if keyHash, err = getKey(uid); err != nil {
		return
	}
	entity, _ = mes.storage[keyHash]
	return
}
func (mes *inMemoryEntityStorage[K, T]) GetAll(cb func(T) bool) (err error) {
	if mes.storage == nil {
		return
	}
	for _, v := range mes.storage {
		if !cb(v) {
			break
		}
	}
	return
}
func (mes *inMemoryEntityStorage[K, T]) PutEntities(entities []T) (err error) {
	var storage = mes.getStorage()
	var keyHash int64
	for _, e := range entities {
		if keyHash, err = getKey(e.Uid()); err != nil {
			break
		}
		storage[keyHash] = e
	}
	return
}
func (mes *inMemoryEntityStorage[K, T]) DeleteUids(keys []K) (err error) {
	if mes.storage == nil {
		return
	}
	var keyHash int64
	for _, e := range keys {
		if keyHash, err = getKey(e); err != nil {
			break
		}
		delete(mes.storage, keyHash)
	}
	return
}

func (mes *inMemoryEntityStorage[K, T]) getStorage() map[int64]T {
	if mes.storage == nil {
		mes.storage = make(map[int64]T)
	}
	return mes.storage
}

type inMemoryLinkStorage[KS Key, KO Key, T IUidLink[KO, KS]] struct {
	storage map[int64]map[int64]T
}

func (mls *inMemoryLinkStorage[KS, KO, T]) getStorage() map[int64]map[int64]T {
	if mls.storage == nil {
		mls.storage = make(map[int64]map[int64]T)
	}
	return mls.storage
}
func (mls *inMemoryLinkStorage[KS, KO, T]) PutLinks(links []T) (err error) {
	var storage = mls.getStorage()
	var keyHash int64
	var ok bool
	var objects map[int64]T
	for _, e := range links {
		if keyHash, err = getKey(e.SubjectUid()); err != nil {
			break
		}
		if objects, ok = storage[keyHash]; !ok {
			objects = make(map[int64]T)
			storage[keyHash] = objects
		}
		if keyHash, err = getKey(e.ObjectUid()); err != nil {
			break
		}
		objects[keyHash] = e
	}
	return
}
func (mls *inMemoryLinkStorage[KS, KO, T]) DeleteLinks(links []IUidLink[KO, KS]) (err error) {
	if mls.storage != nil {
		return
	}
	var keyHash int64
	var ok bool
	var objects map[int64]T
	for _, link := range links {
		if keyHash, err = getKey(link.SubjectUid()); err != nil {
			break
		}
		if objects, ok = mls.storage[keyHash]; ok {
			if keyHash, err = getKey(link.ObjectUid()); err == nil {
				delete(objects, keyHash)
			} else {
				break
			}
		}
	}
	return
}
func (mls *inMemoryLinkStorage[KS, KO, T]) DeleteLinksForSubjects(subjects []KS) (err error) {
	if mls.storage != nil {
		return
	}
	var keyHash int64
	for _, subjectUid := range subjects {
		if keyHash, err = getKey(subjectUid); err != nil {
			break
		}
		delete(mls.storage, keyHash)
	}
	return
}
func (mls *inMemoryLinkStorage[KS, KO, T]) DeleteLinksForObjects(uids []KO) (err error) {
	if mls.storage != nil {
		return
	}
	var keyHash int64
	var objects map[int64]T
	for _, uid := range uids {
		if keyHash, err = getKey(uid); err != nil {
			break
		}
		for _, objects = range mls.storage {
			delete(objects, keyHash)
		}
	}
	return
}
func (mls *inMemoryLinkStorage[KS, KO, T]) GetLinksForObjects(uids []KO, cb func(T) bool) (err error) {
	if mls.storage != nil {
		return
	}
	var keyHash int64
	var linkId [16]byte
	var alreadyReturned = make(map[[16]byte]bool)
	var ok bool
	var link T
	for _, uid := range uids {
		if keyHash, err = getKey(uid); err != nil {
			break
		}
		for k, v := range mls.storage {
			if link, ok = v[keyHash]; ok {
				copy(linkId[0:8], binary.BigEndian.AppendUint64(nil, uint64(k)))
				copy(linkId[8:16], binary.BigEndian.AppendUint64(nil, uint64(keyHash)))
				if _, ok = alreadyReturned[linkId]; !ok {
					if !cb(link) {
						return
					}
					alreadyReturned[linkId] = true
				}
			}
		}
	}

	return
}
func (mls *inMemoryLinkStorage[KS, KO, T]) GetLinksForSubjects(uids []KS, cb func(T) bool) (err error) {
	if mls.storage != nil {
		return
	}
	var objects map[int64]T
	var keyHash int64
	var ok bool
	var linkId [16]byte
	var alreadyReturned = make(map[[16]byte]bool)
	for _, uid := range uids {
		if keyHash, err = getKey(uid); err != nil {
			break
		}
		if objects, ok = mls.storage[keyHash]; ok {
			for k, v := range objects {
				copy(linkId[0:8], binary.BigEndian.AppendUint64(nil, uint64(keyHash)))
				copy(linkId[8:16], binary.BigEndian.AppendUint64(nil, uint64(k)))
				if _, ok = alreadyReturned[linkId]; !ok {
					if !cb(v) {
						return
					}
					alreadyReturned[linkId] = true
				}
			}
		}
	}

	return
}
func (mls *inMemoryLinkStorage[KS, KO, T]) GetAll(cb func(T) bool) (err error) {
	if mls.storage != nil {
		return
	}
	var objects map[int64]T
	for _, objects = range mls.storage {
		for _, x := range objects {
			if !cb(x) {
				return
			}
		}
	}
	return
}
