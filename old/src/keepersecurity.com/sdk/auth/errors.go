package auth

import (
	"fmt"
)

type KeeperCanceled struct {
}
func NewKeeperCanceled() *KeeperCanceled {
	return &KeeperCanceled{}
}
func (e *KeeperCanceled) Error() string {
	return "Canceled"
}


type KeeperAuthFailed struct {
}
func NewKeeperAuthFailed() *KeeperAuthFailed {
	return &KeeperAuthFailed{}
}
func (e *KeeperAuthFailed) Error() string {
	return "Auth Failed"
}

type KeeperError struct {
	message string
}

func NewKeeperError(message string) *KeeperError {
	return &KeeperError{
		message:  message,
	}
}

func (e *KeeperError) Error() string {
	return e.message
}

func (e *KeeperError) Message() string {
	return e.message
}

type KeeperApiError struct {
	KeeperError
	resultCode string
}

func NewKeeperApiError(resultCode string, message string) *KeeperApiError {
	return &KeeperApiError{
		KeeperError:  KeeperError{
			message: message,
		},
		resultCode: resultCode,
	}
}

func (e *KeeperApiError) Error() string {
	return fmt.Sprintf("%s: %s", e.resultCode, e.message)
}

func (e *KeeperApiError) ResultCode() string {
	return e.resultCode
}

type KeeperRegionRedirect struct {
	KeeperError
	regionHost string
}

func NewKeeperRegionRedirect(regionHost string, additionalInfo string) *KeeperRegionRedirect {
	return &KeeperRegionRedirect{
		KeeperError: KeeperError{
			message: additionalInfo,
		},
		regionHost: regionHost,
	}
}

func (e *KeeperRegionRedirect) Error() string {
	return fmt.Sprintf("Keeper region switch requested: %s", e.regionHost)
}

func (e *KeeperRegionRedirect) RegionHost() string {
	return e.regionHost
}
/*
type KeeperInvalidDeviceToken struct {
	KeeperError
}

func NewKeeperInvalidDeviceToken(additionalInfo string) *KeeperInvalidDeviceToken {
	return &KeeperInvalidDeviceToken{
		KeeperError: KeeperError{
			message: additionalInfo,
		},
	}
}

func (e *KeeperInvalidDeviceToken) Error() string {
	return fmt.Sprintf("Additional info: %s", e.message)
}
*/