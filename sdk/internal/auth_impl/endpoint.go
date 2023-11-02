package auth_impl

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_auth"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
	"net/url"
	"time"
)

const ClientVersion = "c16.9.0"
const DefaultLocale = "en_US"
const DefaultDeviceName = "GoLang Keeper API"
const DefaultKeeperServer = "keepersecurity.com"

func PrepareApiRequest(keyId int32, payload []byte, transmissionKey []byte, sessionToken []byte, locale string) (result *proto_auth.ApiRequest, err error) {
	requestPayload := &proto_auth.ApiRequestPayload{
		ApiVersion: 3,
		Payload:    payload,
	}
	if sessionToken != nil {
		requestPayload.EncryptedSessionToken = sessionToken
	}

	var ok bool
	var encKey []byte
	if keyId <= 6 {
		var pubKey *rsa.PublicKey
		if pubKey, ok = serverRsaPublicKeys[keyId]; ok {
			if encKey, err = api.EncryptRsa(transmissionKey, pubKey); err != nil {
				return
			}
		} else {
			err = api.NewKeeperError(fmt.Sprintf("Invalid Keeper Server Key ID: %d", keyId))
		}
	} else {
		var pubKey *ecdh.PublicKey
		if pubKey, ok = serverEcPublicKeys[keyId]; ok {
			if encKey, err = api.EncryptEc(transmissionKey, pubKey); err != nil {
				return
			}
		} else {
			err = api.NewKeeperError(fmt.Sprintf("Invalid Keeper Server Key ID: %d", keyId))
		}
	}

	var rqPayload []byte
	if rqPayload, err = proto.Marshal(requestPayload); err != nil {
		return
	}
	var encPayload []byte
	if encPayload, err = api.EncryptAesV2(rqPayload, transmissionKey); err != nil {
		return
	}

	result = &proto_auth.ApiRequest{
		EncryptedTransmissionKey: encKey,
		PublicKeyId:              keyId,
		Locale:                   locale,
		EncryptedPayload:         encPayload,
	}
	return
}

type keeperEndpoint struct {
	clientVersion string
	deviceName    string
	locale        string
	server        string
	serverKeyId   int32
	storage       auth.IConfigurationStorage
}

func (endpoint *keeperEndpoint) ConfigurationStorage() auth.IConfigurationStorage {
	return endpoint.storage
}
func (endpoint *keeperEndpoint) ClientVersion() string {
	return endpoint.clientVersion
}
func (endpoint *keeperEndpoint) SetClientVersion(version string) {
	endpoint.clientVersion = version
}

func (endpoint *keeperEndpoint) Server() string {
	if endpoint.server == "" {
		return DefaultKeeperServer
	}
	return endpoint.server
}
func (endpoint *keeperEndpoint) SetServer(server string) {
	endpoint.server = server
}

func (endpoint *keeperEndpoint) DeviceName() string {
	return endpoint.deviceName
}
func (endpoint *keeperEndpoint) SetDeviceName(deviceName string) {
	endpoint.deviceName = deviceName
}

func (endpoint *keeperEndpoint) Locale() string {
	return endpoint.locale
}
func (endpoint *keeperEndpoint) SetLocale(locale string) {
	endpoint.locale = locale
}

func (endpoint *keeperEndpoint) ServerKeyId() int32 {
	return endpoint.serverKeyId
}

func (endpoint *keeperEndpoint) CommunicateKeeper(path string, request []byte, sessionToken []byte) (response []byte, err error) {
	var logger = api.GetLogger()
	uri := new(url.URL)
	uri.Scheme = "https"
	uri.Host = endpoint.Server()
	uri.Path = "/api/rest/"
	ep, _ := url.Parse(path)
	uri = uri.ResolveReference(ep)

	var transmissionKey = api.GenerateAesKey()
	var serverKey = endpoint.serverKeyId
	if serverKey < 1 || serverKey > 17 {
		serverKey = 7
	}
	client := http.DefaultClient
	for attempt := 0; attempt < 3; attempt++ {

		var apiRequest *proto_auth.ApiRequest
		if apiRequest, err = PrepareApiRequest(serverKey, request, transmissionKey, sessionToken, endpoint.Locale()); err != nil {
			return
		}
		var rqBody []byte
		if rqBody, err = proto.Marshal(apiRequest); err != nil {
			logger.Warn("Protobuf serialize error", zap.Error(err))
			return
		}
		var rq *http.Request
		if rq, err = http.NewRequest("POST", uri.String(), bytes.NewReader(rqBody)); err != nil {
			return
		}
		rq.Header.Set("Content-Type", "application/octet-stream")
		var rs *http.Response
		if rs, err = client.Do(rq); err != nil {
			logger.Warn("HTTP request error", zap.Error(err))
			return
		}
		var body []byte
		if rs.StatusCode == 200 && rs.Header.Get("Content-Type") == "application/octet-stream" {
			if serverKey != endpoint.serverKeyId && endpoint.storage != nil {
				var conf auth.IKeeperConfiguration
				if conf, err = endpoint.storage.Get(); err == nil {
					var sc = auth.NewServerConfiguration(endpoint.server)
					sc.SetServerKeyId(endpoint.serverKeyId)
					conf.Servers().Put(sc)
					err = endpoint.storage.Put(conf)
					if err != nil {
						logger.Warn("Store configuration error", zap.Error(err))
					}
				} else {
					logger.Warn("Read configuration error", zap.Error(err))
				}
			}
			if body, err = io.ReadAll(rs.Body); err == nil {
				if body != nil && len(body) > 0 {
					response, err = api.DecryptAesV2(body, transmissionKey)
				} else {
					response = nil
				}
			}
		} else if rs.Header.Get("Content-Type") == "application/json" {
			if body, err = io.ReadAll(rs.Body); err == nil {
				var apiError auth.KeeperApiErrorResponse
				if err = json.Unmarshal(body, &apiError); err == nil {
					switch apiError.Error {
					case "key":
						serverKey = apiError.KeyId
					case "region_redirect":
						err = api.NewKeeperRegionRedirect(apiError.RegionHost, apiError.AdditionalInfo)
					case "device_not_registered":
						err = api.NewKeeperInvalidDeviceToken(apiError.AdditionalInfo)
					case "throttled":
						time.Sleep(time.Second * 10)
					default:
						err = api.NewKeeperApiError(apiError.ResultCode, apiError.Message)
					}
				}
			}
		} else {
			err = api.NewKeeperError(fmt.Sprintf("Keeper http request status: %d", rs.StatusCode))
		}
		_ = rs.Body.Close()
		if err != nil || response != nil {
			return
		}
	}
	err = api.NewKeeperError("Keeper endpoint: too many attempts")
	return
}

func (endpoint *keeperEndpoint) PushServer() string {
	return "push.services." + endpoint.Server()
}

func (endpoint *keeperEndpoint) ConnectToPushServer(wssRequest *proto_auth.WssConnectionRequest) (result auth.IPushEndpoint, err error) {
	var payload []byte
	if payload, err = proto.Marshal(wssRequest); err != nil {
		return
	}
	var transmissionKey = api.GenerateAesKey()
	var rq *proto_auth.ApiRequest
	if rq, err = PrepareApiRequest(endpoint.ServerKeyId(), payload, transmissionKey, nil, endpoint.Locale()); err != nil {
		return
	}

	var rqBody []byte
	if rqBody, err = proto.Marshal(rq); err != nil {
		return
	}

	pushUrl := new(url.URL)
	pushUrl.Scheme = "wss"
	pushUrl.Host = endpoint.PushServer()
	pushUrl.Path = "/wss_open_connection/" + api.Base64UrlEncode(rqBody)

	result = auth.NewWebSocketEndpoint(pushUrl.String(), transmissionKey)
	return
}

func NewKeeperEndpoint(server string, storage auth.IConfigurationStorage) auth.IKeeperEndpoint {
	var endpoint = &keeperEndpoint{
		clientVersion: ClientVersion,
		locale:        DefaultLocale,
		deviceName:    DefaultDeviceName,
		server:        auth.AdjustServerName(server),
		serverKeyId:   7,
		storage:       storage,
	}

	if conf, err := storage.Get(); err != nil {
		var sc = conf.Servers().Get(endpoint.Server())
		if sc != nil {
			endpoint.serverKeyId = sc.ServerKeyId()
		}
	}
	return endpoint
}

func tryLoadRsaPublicKey(pem string) *rsa.PublicKey {
	key, err := api.LoadRsaPublicKey(api.Base64UrlDecode(pem))
	if err != nil {
		panic(err)
	}
	return key
}

func tryLoadEcPublicKey(pem string) *ecdh.PublicKey {
	key, err := api.LoadEcPublicKey(api.Base64UrlDecode(pem))
	if err != nil {
		panic(err)
	}
	return key
}

var publicKey1 = tryLoadRsaPublicKey("MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH" +
	"OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn" +
	"j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb" +
	"_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V" +
	"xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB" +
	"6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB")

var publicKey2 = tryLoadRsaPublicKey("MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq" +
	"YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY" +
	"KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd" +
	"WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl" +
	"BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN" +
	"ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB")

var publicKey3 = tryLoadRsaPublicKey("MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI" +
	"hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi" +
	"rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS" +
	"HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N" +
	"Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE" +
	"AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB")

var publicKey4 = tryLoadRsaPublicKey("MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR" +
	"FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H" +
	"CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX" +
	"-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ" +
	"KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5" +
	"osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB")

var publicKey5 = tryLoadRsaPublicKey("MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv" +
	"sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH" +
	"FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_" +
	"uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV" +
	"hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO" +
	"WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB")

var publicKey6 = tryLoadRsaPublicKey("MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL" +
	"AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v" +
	"w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl" +
	"_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-" +
	"ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ" +
	"17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB")

var publicKey7 = tryLoadEcPublicKey(
	"BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM")

var publicKey8 = tryLoadEcPublicKey(
	"BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ")

var publicKey9 = tryLoadEcPublicKey(
	"BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g")

var publicKey10 = tryLoadEcPublicKey(
	"BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg")

var publicKey11 = tryLoadEcPublicKey(
	"BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk")

var publicKey12 = tryLoadEcPublicKey(
	"BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY")

var publicKey13 = tryLoadEcPublicKey(
	"BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI")

var publicKey14 = tryLoadEcPublicKey(
	"BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE")

var publicKey15 = tryLoadEcPublicKey(
	"BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8")

var publicKey16 = tryLoadEcPublicKey(
	"BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c")

var publicKey17 = tryLoadEcPublicKey(
	"BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU")

var serverRsaPublicKeys = map[int32]*rsa.PublicKey{
	1: publicKey1,
	2: publicKey2,
	3: publicKey3,
	4: publicKey4,
	5: publicKey5,
	6: publicKey6,
}
var serverEcPublicKeys = map[int32]*ecdh.PublicKey{
	7:  publicKey7,
	8:  publicKey8,
	9:  publicKey9,
	10: publicKey10,
	11: publicKey11,
	12: publicKey12,
	13: publicKey13,
	14: publicKey14,
	15: publicKey15,
	16: publicKey16,
	17: publicKey17,
}
