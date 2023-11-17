package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_enterprise"
	"go.uber.org/zap"
)

type enterpriseLoader struct {
	keeperAuth        auth.IKeeperAuth
	storage           IEnterpriseStorage
	enterpriseData    *enterpriseData
	continuationToken []byte
}

func (el *enterpriseLoader) Storage() IEnterpriseStorage {
	return el.storage
}

func (el *enterpriseLoader) EnterpriseData() IEnterpriseData {
	return el.enterpriseData
}

func (el *enterpriseLoader) KeeperAuth() auth.IKeeperAuth {
	return el.keeperAuth
}

func (el *enterpriseLoader) Load() (err error) {
	var logger = api.GetLogger()
	if el.enterpriseData == nil {
		var ei = new(enterpriseInfo)
		var rqKeys = new(proto_enterprise.GetEnterpriseDataKeysRequest)
		var rsKeys = new(proto_enterprise.GetEnterpriseDataKeysResponse)
		if err = el.keeperAuth.ExecuteAuthRest("enterprise/get_enterprise_data_keys", rqKeys, rsKeys); err != nil {
			return
		}
		var data []byte
		data = api.Base64UrlDecode(rsKeys.TreeKey.TreeKey)
		var keyType = rsKeys.TreeKey.KeyTypeId
		switch keyType {
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_DATA_KEY:
			ei.treeKey, err = api.DecryptAesV1(data, el.keeperAuth.AuthContext().DataKey())
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_DATA_KEY_GCM:
			ei.treeKey, err = api.DecryptAesV2(data, el.keeperAuth.AuthContext().DataKey())
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_PUBLIC_KEY:
			ei.treeKey, err = api.DecryptRsa(data, el.keeperAuth.AuthContext().RsaPrivateKey())
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_PUBLIC_KEY_ECC:
			ei.treeKey, err = api.DecryptEc(data, el.keeperAuth.AuthContext().EcPrivateKey())
		default:
			err = api.NewKeeperError(fmt.Sprintf("Tree key encryption type %s is not supported", keyType.String()))
		}
		if err != nil {
			return
		}
		if len(rsKeys.EnterpriseKeys.RsaEncryptedPrivateKey) > 0 {
			if data, err = api.DecryptAesV2(rsKeys.EnterpriseKeys.RsaEncryptedPrivateKey, ei.treeKey); err == nil {
				ei.rsaPrivateKey, err = api.LoadRsaPrivateKey(data)
			}
		} else {
			var privKey *rsa.PrivateKey
			var pubKey *rsa.PublicKey
			if privKey, pubKey, err = api.GenerateRsaKey(); err == nil {
				data = api.UnloadRsaPrivateKey(privKey)
				if data, err = api.EncryptAesV2(data, ei.treeKey); err == nil {
					var rqSetKey = &proto_enterprise.EnterpriseKeyPairRequest{
						EnterprisePublicKey:           api.UnloadRsaPublicKey(pubKey),
						EncryptedEnterprisePrivateKey: data,
						KeyType:                       proto_enterprise.KeyType_RSA,
					}
					if err = el.keeperAuth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", rqSetKey, nil); err == nil {
						ei.rsaPrivateKey = privKey
					}
				}
			}
		}
		if err != nil {
			logger.Warn("Error loading enterprise RSA key", zap.Error(err))
			err = nil
		}
		if len(rsKeys.EnterpriseKeys.EccEncryptedPrivateKey) > 0 {
			if data, err = api.DecryptAesV2(rsKeys.EnterpriseKeys.EccEncryptedPrivateKey, ei.treeKey); err == nil {
				ei.ecPrivateKey, err = api.LoadEcPrivateKey(data)
			}
		} else {
			var privKey *ecdh.PrivateKey
			var pubKey *ecdh.PublicKey
			if privKey, pubKey, err = api.GenerateEcKey(); err == nil {
				data = api.UnloadEcPrivateKey(privKey)
				if data, err = api.EncryptAesV2(data, ei.treeKey); err == nil {
					var rqSetKey = &proto_enterprise.EnterpriseKeyPairRequest{
						EnterprisePublicKey:           api.UnloadEcPublicKey(pubKey),
						EncryptedEnterprisePrivateKey: data,
						KeyType:                       proto_enterprise.KeyType_ECC,
					}
					if err = el.keeperAuth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", rqSetKey, nil); err == nil {
						ei.ecPrivateKey = privKey
					}
				}
			}
		}
		if err != nil {
			logger.Warn("Error loading enterprise ECC key", zap.Error(err))
			err = nil
		}

		el.enterpriseData = newEnterpriseData(ei)
	}

	var treeKey = el.enterpriseData.enterpriseInfo.treeKey
	if el.continuationToken == nil {
		if el.storage != nil {
			if err = el.storage.GetEntities(func(entityType int32, entityData []byte) bool {
				var et = proto_enterprise.EnterpriseDataEntity(entityType)
				if plugin := el.enterpriseData.getEnterprisePlugin(et); plugin != nil {
					var _, _ = plugin.store(entityData, treeKey)
				}
				return true
			}); err != nil {
				return
			}
			if el.continuationToken, err = el.storage.ContinuationToken(); err != nil {
				logger.Warn("Error loading enterprise settings", zap.Error(err))
				el.continuationToken = nil
			}
		}
	}

	for {
		var rqData = &proto_enterprise.EnterpriseDataRequest{}
		if el.continuationToken != nil {
			rqData.ContinuationToken = el.continuationToken
		}
		var rsData = new(proto_enterprise.EnterpriseDataResponse)
		if err = el.keeperAuth.ExecuteAuthRest("enterprise/get_enterprise_data_for_user", rqData, rsData); err != nil {
			return
		}
		if rsData.GetCacheStatus() == proto_enterprise.CacheStatus_CLEAR {
			if el.storage != nil {
				el.storage.Clear()
			}
			for _, x := range el.enterpriseData.getSupportedEntities() {
				if plugin := el.enterpriseData.getEnterprisePlugin(x); plugin != nil {
					plugin.clear()
				}
			}
		}
		if len(el.enterpriseData.enterpriseInfo.enterpriseName) == 0 {
			el.enterpriseData.enterpriseInfo.enterpriseName = rsData.GetGeneralData().GetEnterpriseName()
			el.enterpriseData.enterpriseInfo.isDistributor = rsData.GetGeneralData().GetDistributor()
		}

		for _, ed := range rsData.Data {
			var entityType = ed.GetEntity()
			plugin := el.enterpriseData.getEnterprisePlugin(entityType)
			if plugin == nil {
				continue
			}
			for _, edd := range ed.GetData() {
				var storageKey string
				if ed.GetDelete() {
					if storageKey, err = plugin.delete(edd); err != nil {
						break
					}
					if el.storage != nil {
						err = el.Storage().DeleteEntity(int32(entityType), storageKey)
					}
				} else {
					if storageKey, err = plugin.store(edd, treeKey); err != nil {
						break
					}
					if el.storage != nil {
						err = el.Storage().PutEntity(int32(entityType), storageKey, edd)
					}
				}

				if err != nil {
					break
				}
			}
		}
		if err != nil {
			break
		}
		if el.storage != nil {
			_ = el.Storage().SetContinuationToken(rsData.ContinuationToken)
			err = el.Storage().Flush()
		}
		el.continuationToken = rsData.ContinuationToken
		if !rsData.GetHasMore() {
			break
		}
	}

	var ed = el.enterpriseData
	if ed.rootNode == nil {
		ed.Nodes().GetAllEntities(
			func(node INode) bool {
				if node.ParentId() == 0 {
					if n, ok := node.(INodeEdit); ok {
						n.SetName(ed.enterpriseInfo.enterpriseName)
					}
					ed.rootNode = node
					return false
				}
				return true
			})
	}
	return
}

func NewEnterpriseLoader(keeperAuth auth.IKeeperAuth, storage IEnterpriseStorage) IEnterpriseLoader {
	return &enterpriseLoader{
		keeperAuth: keeperAuth,
		storage:    storage,
	}
}
