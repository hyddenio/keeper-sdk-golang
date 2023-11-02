package auth

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"google.golang.org/protobuf/proto"
	"keepersecurity.com/sdk/protobuf/authentication"
	"keepersecurity.com/sdk/protobuf/push"
)

const ClientVersion = "c15.0.0"
const DefaultLocale = "en_US"
const DefaultDeviceName = "GoLang Keeper API"
const defaultKeeperServer = "keepersecurity.com"

type IKeeperEndpoint interface {
	ClientVersion() string
	SetClientVersion(string)
	DeviceName() string
	SetDeviceName(string)
	Locale() string
	SetLocale(string)
	Server() string
	SetServer(string)
	ServerKeyId() int32

	PrepareApiRequest(request []byte, transmissionKey []byte, sessionToken []byte) (*authentication.ApiRequest, error)
	ExecuteRest(string, []byte, []byte) ([]byte, error)

	PushServer() string
	ConnectToPushServer(*push.WssConnectionRequest) (IPushEndpoint, error)
}

type keeperEndpoint struct {
	clientVersion   string
	deviceName      string
	locale          string
	server          string
	serverKeyId     int32
	storage         IServerCollection
}

func NewKeeperEndpoint(server string, storage IServerCollection) IKeeperEndpoint {
	var endpoint = &keeperEndpoint{
		clientVersion:   ClientVersion,
		locale:          DefaultLocale,
		deviceName:      DefaultDeviceName,
		server:          server,
		serverKeyId:     1,
		storage:         storage,
	}

	if storage != nil {
		if sc := storage.Get(endpoint.Server()); sc != nil {
			endpoint.serverKeyId = sc.ServerKeyId()
		}
	}
	return endpoint
}
func (endpoint *keeperEndpoint) ClientVersion() string {
	return endpoint.clientVersion
}
func (endpoint *keeperEndpoint) SetClientVersion(version string) {
	endpoint.clientVersion = version
}

func (endpoint *keeperEndpoint) Server() string {
	if endpoint.server == "" {
		return defaultKeeperServer
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

func (endpoint *keeperEndpoint) ExecuteRest(path string, request []byte, sessionToken []byte) (response []byte, err error) {
	uri := new(url.URL)
	uri.Scheme = "https"
	uri.Host = endpoint.Server()
	uri.Path = "/api/rest/"
	ep, _ := url.Parse(path)
	uri = uri.ResolveReference(ep)

	var transmissionKey = GenerateAesKey()
	var serverKey = endpoint.serverKeyId
	client := http.DefaultClient
	for attempt := 0; attempt < 3; attempt++ {

		var apiRequest *authentication.ApiRequest
		if apiRequest, err = endpoint.PrepareApiRequest(request, transmissionKey, sessionToken); err != nil {
			return
		}
		var rqBody []byte
		if rqBody, err = proto.Marshal(apiRequest); err != nil {
			return
		}
		var rq *http.Request
		if rq, err = http.NewRequest("POST", uri.String(), bytes.NewReader(rqBody)); err != nil {
			return
		}
		rq.Header.Set("Content-Type", "application/octet-stream")
		var rs *http.Response
		if rs, err = client.Do(rq); err != nil {
			return
		}
		var body []byte
		if rs.StatusCode == 200 && rs.Header.Get("Content-Type") == "application/octet-stream" {
			if serverKey != endpoint.serverKeyId && endpoint.storage != nil {
				var sc = NewServerConfiguration(endpoint.server)
				sc.ServerKeyId_ = endpoint.serverKeyId
				endpoint.storage.Put(sc)
			}
			if body, err = ioutil.ReadAll(rs.Body); err == nil {
				if body != nil && len(body) > 0 {
					response, err = DecryptAesV2(body, transmissionKey)
				} else {
					response = nil
				}
			}
		} else if rs.Header.Get("Content-Type") == "application/json" {
			if body, err = ioutil.ReadAll(rs.Body); err == nil {
				var apiError KeeperApiErrorResponse
				if err = json.Unmarshal(body, &apiError); err == nil {
					switch apiError.Error {
					case "key":
						endpoint.serverKeyId = apiError.KeyId
					case "region_redirect":
						err = NewKeeperRegionRedirect(apiError.RegionHost, apiError.AdditionalInfo)
					case "session_token":
					case "auth_failed":
						err = NewKeeperAuthFailed()
					case "login_token_expired":
						err = NewKeeperCanceled();
					default:
						err = NewKeeperApiError(apiError.ResultCode, apiError.Message)
					}
				}
			}
		} else {
			err = NewKeeperError(fmt.Sprintf("Keeper http request status: %d", rs.StatusCode))
		}
		_ = rs.Body.Close()
		if err != nil || response != nil {
			return
		}
	}
	err = NewKeeperError("Keeper endpoint: too many attempts")
	return
}

func (endpoint *keeperEndpoint) PushServer() string {
	return "push.services." + endpoint.Server()
}

func (endpoint *keeperEndpoint) ConnectToPushServer(wssRequest *push.WssConnectionRequest) (result IPushEndpoint, err error) {
	var payload []byte
	if payload, err = proto.Marshal(wssRequest); err != nil {
		return
	}
	var transmissionKey = GenerateAesKey()
	var rq *authentication.ApiRequest
	if rq, err = endpoint.PrepareApiRequest(payload, transmissionKey, nil); err != nil {
		return
	}

	var rqBody []byte
	if rqBody, err = proto.Marshal(rq); err != nil {
		return
	}

	url := new(url.URL)
	url.Scheme = "wss"
	url.Host = endpoint.PushServer()
	url.Path = "/wss_open_connection/" + Base64UrlEncode(rqBody)

	result, err = NewWebSocketEndpoint(url.String(), transmissionKey)

	return
}

func (endpoint *keeperEndpoint) PrepareApiRequest(payload []byte, transmissionKey []byte, sessionToken []byte) (result *authentication.ApiRequest, err error) {
	requestPayload := &authentication.ApiRequestPayload{
		ApiVersion: 3,
		Payload:    payload,
	}
	if sessionToken != nil {
		requestPayload.EncryptedSessionToken = sessionToken
	}

	var pubKey crypto.PublicKey
	var ok bool
	if pubKey, ok = serverPublicKeys[endpoint.serverKeyId]; !ok {
		endpoint.serverKeyId = 1
		pubKey, ok = serverPublicKeys[endpoint.serverKeyId]
	}

	var encKey []byte
	if encKey, err = EncryptRsa(transmissionKey, pubKey); err != nil {
		return
	}

	var rqPayload []byte
	if rqPayload, err = proto.Marshal(requestPayload); err != nil {
		return
	}
	var encPayload []byte
	if encPayload, err = EncryptAesV2(rqPayload, transmissionKey); err != nil {
		return
	}

	result = &authentication.ApiRequest{
		EncryptedTransmissionKey: encKey,
		PublicKeyId:              endpoint.serverKeyId,
		Locale:                   endpoint.locale,
		EncryptedPayload:         encPayload,
	}
	return
}

func tryLoadPublicKey(pem string) crypto.PublicKey {
	key, err := LoadRsaPublicKey(Base64UrlDecode(pem))
	if err != nil {
		panic(err)
	}
	return key
}

var publicKey1 = tryLoadPublicKey("MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH" +
	"OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn" +
	"j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb" +
	"_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V" +
	"xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB" +
	"6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB")

var publicKey2 = tryLoadPublicKey("MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq" +
	"YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY" +
	"KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd" +
	"WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl" +
	"BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN" +
	"ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB"	)

var publicKey3 = tryLoadPublicKey("MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI" +
	"hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi" +
	"rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS" +
	"HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N" +
	"Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE" +
	"AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB")

var publicKey4 = tryLoadPublicKey("MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR" +
	"FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H" +
	"CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX" +
	"-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ" +
	"KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5" +
	"osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB")

var publicKey5 = tryLoadPublicKey("MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv" +
	"sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH" +
	"FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_" +
	"uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV" +
	"hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO" +
	"WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB")

var publicKey6 = tryLoadPublicKey("MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL" +
	"AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v" +
	"w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl" +
	"_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-" +
	"ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ" +
	"17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB")

var serverPublicKeys = map[int32]crypto.PublicKey {
	1: publicKey1,
	2: publicKey2,
	3: publicKey3,
	4: publicKey4,
	5: publicKey5,
	6: publicKey6,
}
