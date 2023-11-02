package helpers

import (
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/auth_impl"
)

func NewKeeperEndpoint(server string, storage auth.IConfigurationStorage) auth.IKeeperEndpoint {
	return auth_impl.NewKeeperEndpoint(server, storage)
}

func NewLoginAuth(endpoint auth.IKeeperEndpoint) auth.ILoginAuth {
	return auth_impl.NewLoginAuth(endpoint)
}

func NewJsonConfigurationFile(filePath string) auth.IConfigurationStorage {
	return auth_impl.NewJsonConfigurationFile(filePath)
}

func NewJsonConfigurationStorage(loader auth.IJsonConfigurationLoader) auth.IConfigurationStorage {
	return auth_impl.NewJsonConfigurationStorage(loader)
}

func NewJsonConfigurationFileLoader(filename string) auth.IJsonConfigurationLoader {
	return auth_impl.NewJsonConfigurationFileLoader(filename)
}

func NewCommanderConfiguration(filePath string) auth.IConfigurationStorage {
	return auth_impl.NewCommanderConfiguration(filePath)
}
