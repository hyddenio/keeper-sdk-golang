package sdk

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"keepersecurity.com/sdk/protobuf"
	"net/http"
	"net/url"
	"strings"
)

const ClientVersion = "c14.0.0"
const DefaultLocale = "en_US"
const DefaultDeviceName = "GoLang Keeper API"
const defaultKeeperServer = "keepersecurity.com"

type KeeperEndpoint interface {
	Server() string
	DeviceToken() []byte
	ServerKeyId() int32
	SetServerParams(string, []byte, int32)
	GetDeviceToken() ([]byte, error)
	InvalidateDeviceToken()
	ExecuteRest(string, []byte) ([]byte, error)
	GetNewUserParams(string) (*protobuf.NewUserMinimumParams, error)
	ExecuteV2Command(interface{}, interface{}) error
	ClientVersion() string
}

type keeperEndpoint struct {
	clientVersion   string
	deviceName      string
	locale          string
	server          string
	serverKeyId     int32
	deviceToken     []byte
	transmissionKey []byte
}

func NewKeeperEndpoint() KeeperEndpoint {
	return & keeperEndpoint {
		clientVersion: ClientVersion,
		locale:DefaultLocale,
		deviceName: DefaultDeviceName,
	}
}
func (endpoint *keeperEndpoint) ClientVersion() string {
	return endpoint.clientVersion
}
func (endpoint *keeperEndpoint) Server() string {
	return endpoint.server
}
func (endpoint *keeperEndpoint) DeviceToken() []byte {
	return endpoint.deviceToken
}
func (endpoint *keeperEndpoint) ServerKeyId() int32 {
	return endpoint.serverKeyId
}

func (endpoint *keeperEndpoint) SetServerParams(server string, deviceToken []byte, serverKeyId int32) {
	endpoint.server = server
	endpoint.deviceToken = deviceToken
	endpoint.serverKeyId = serverKeyId
	endpoint.transmissionKey = nil
}

func (endpoint *keeperEndpoint)	InvalidateDeviceToken() {
	endpoint.deviceToken = nil
}

func (endpoint *keeperEndpoint) ExecuteRest(path string, payload []byte) ([]byte, error) {
	if endpoint.transmissionKey == nil {
		endpoint.transmissionKey = GetRandomBytes(32)
	}
	var server = endpoint.server
	if server == "" {
		server = defaultKeeperServer
	}
	uri := new(url.URL)
	uri.Scheme = "https"
	uri.Host = server
	uri.Path = "/api/rest/"
	ep, _ := url.Parse(path)
	uri = uri.ResolveReference(ep)

	apiPayload := &protobuf.ApiRequestPayload{
		Payload: payload,
	}
	rqPayload, err := proto.Marshal(apiPayload)
	if err != nil {
		return nil, err
	}
	client := http.DefaultClient
	for attempt := 0; attempt < 3; attempt++ {
		encPayload, err := EncryptAesV2(rqPayload, endpoint.transmissionKey)
		if err != nil {
			return nil, err
		}
		var pubKey crypto.PublicKey
		var ok bool
		if pubKey, ok = serverPublicKeys[endpoint.serverKeyId]; !ok {
			endpoint.serverKeyId = 1
			pubKey, ok = serverPublicKeys[endpoint.serverKeyId]
		}
		encKey, err := EncryptRsa(endpoint.transmissionKey, pubKey)
		apiRequest := &protobuf.ApiRequest{
			EncryptedTransmissionKey: encKey,
			PublicKeyId: int32(endpoint.serverKeyId),
			Locale: endpoint.locale,
			EncryptedPayload: encPayload,
		}
		rqBody, err := proto.Marshal(apiRequest)
		if err != nil {
			return nil, err
		}
		rq, err := http.NewRequest("POST", uri.String(), bytes.NewReader(rqBody))
		if err != nil {
			return nil, err
		}
		rq.Header.Set("Content-Type", "application/octet-stream")
		rs, err := client.Do(rq)
		if err != nil {
			return nil, err
		}
		if rs.StatusCode == 200 && rs.Header.Get("Content-Type") == "application/octet-stream" {
			body, err := ioutil.ReadAll(rs.Body)
			_ = rs.Body.Close()
			if err != nil {
				return nil, err
			}
			return DecryptAesV2(body, endpoint.transmissionKey)
		}
		if rs.Header.Get("Content-Type") == "application/json" {
			body, err := ioutil.ReadAll(rs.Body)
			if err != nil {
				return nil, err
			}
			var apiError KeeperApiErrorResponse
			err = json.Unmarshal(body, &apiError)
			if err != nil {
				return nil, err
			}
			switch apiError.Error {
			case "key":
				endpoint.serverKeyId = apiError.KeyId
				continue
			case "region_redirect":
				return nil, NewKeeperRegionRedirect(apiError.RegionHost, apiError.AdditionalInfo)
			case "bad_request":
				return nil, NewKeeperInvalidDeviceToken(apiError.AdditionalInfo)
			default:
				return nil, NewKeeperApiError(&apiError.KeeperApiResponse)
			}
		}
		return nil, NewKeeperError(fmt.Sprintf("Keeper http request status: %d", rs.StatusCode))
	}
	return nil, NewKeeperError("Keeper endpoint: too many attempts")
}

func (endpoint *keeperEndpoint) GetDeviceToken() (token []byte, err error) {
	token = endpoint.deviceToken
	err = nil
	if token == nil {
		tokenRq := &protobuf.DeviceRequest{
			ClientVersion: endpoint.clientVersion,
			DeviceName: endpoint.deviceName,
		}
		if rqBody, err := proto.Marshal(tokenRq); err == nil {
			if rs, err := endpoint.ExecuteRest("authentication/get_device_token", rqBody); err == nil {
				tokenRs := &protobuf.DeviceResponse{}
				err = proto.Unmarshal(rs, tokenRs)
				if err == nil {
					if tokenRs.Status == protobuf.DeviceStatus_OK {
						token = tokenRs.EncryptedDeviceToken
						endpoint.deviceToken = token
					} else {
						err = NewKeeperInvalidDeviceToken("Cannot acquire device token")
					}
				}
			}
		}
	}
	return
}

func (endpoint *keeperEndpoint) GetNewUserParams(username string) (params *protobuf.NewUserMinimumParams, err error) {
	params = nil
	deviceToken, err := endpoint.GetDeviceToken()
	if err != nil {
		return
	}
	authRq := &protobuf.AuthRequest{
		ClientVersion: endpoint.clientVersion,
		Username: strings.ToLower(username),
		EncryptedDeviceToken: deviceToken,
	}

	if authBody, err := proto.Marshal(authRq); err == nil {
		if authRs, err := endpoint.ExecuteRest("authentication/get_new_user_params", authBody); err ==  nil {
			params = &protobuf.NewUserMinimumParams{}
			err = proto.Unmarshal(authRs, params)
		}
	}
	return
}

func (endpoint *keeperEndpoint) ExecuteV2Command(rq interface{}, rs interface{}) (err error) {
	if toCmd, ok := rq.(ToKeeperApiCommand); ok {
		apiRq := toCmd.GetKeeperApiCommand()
		apiRq.ClientVersion = endpoint.clientVersion
		apiRq.Locale = endpoint.locale
		if apiRq.Command == "" {
			if cmdName, ok := rq.(ICommand); ok {
				apiRq.Command = cmdName.Command()
			}
		}
	}
	if rqBody, err := json.Marshal(rq); err == nil {
		if rsBody, err := endpoint.ExecuteRest("vault/execute_v2_command", rqBody); err == nil {
			err = json.Unmarshal(rsBody, rs)
		}
	}
	return
}

func tryLoadPublicKey(pem string) crypto.PublicKey {
	key, err := LoadPublicKey(Base64UrlDecode(pem))
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
