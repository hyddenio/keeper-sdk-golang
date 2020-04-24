package main

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"keepersecurity.com/sdk"
	"os"
	"strings"
	"syscall"
)

func main() {
	storage := sdk.NewJsonSettingsStorage("config.json")
	setts := storage.GetSettings()
	email := setts.LastUsername()
	if email == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("\nEnter Email: ")
		email, _ = reader.ReadString('\n')
		email = strings.Replace(email, "\r", "", -1)
		email = strings.Replace(email, "\n", "", -1)
	}
	var password = ""
	if email != "" {
		if us := sdk.GetUserSettings(setts, email); us != nil {
			password = us.Password()
		}
	}
	if password == "" {
		fmt.Print("\nEnter Password: ")
		bytes, _ := terminal.ReadPassword(int(syscall.Stdin))
		password = string(bytes)
	}

	var err error
	var ui BaseUi
	auth := sdk.NewAuth(ui, storage)
	// ensure email and password are not empty
	if err = auth.Login(email, password); err == nil {
		vault := sdk.NewVault(auth, nil)
		if err = vault.SyncDown(); err == nil {
			var record *sdk.PasswordRecord
			vault.GetAllRecords(func (r *sdk.PasswordRecord) bool {
				if len(r.Attachments) > 0 {
					record = r
				}
				return record == nil
			})

			if record != nil {
				var buffer = new(bytes.Buffer)
				if err = vault.DownloadAttachment(record, record.Attachments[0].Id, buffer); err == nil {
					fmt.Println("Downloaded", buffer.Len(), "bytes")
				}
			}
		}
	}
}

type BaseUi struct {}

func (p BaseUi) Confirmation(_ string) bool {
	return false
}
func (p BaseUi) GetNewPassword(_ sdk.PasswordRuleMatcher) string {
	return ""
}
func (p BaseUi) GetTwoFactorCode(channel sdk.TwoFactorChannel) (string, sdk.TwoFactorCodeDuration) {
	fmt.Print("\nEnter Two-Factor Code: ")
	if code, err := terminal.ReadPassword(int(syscall.Stdin)); err == nil {
		return string(code), sdk.Forever
	}
	return "", sdk.Forever
}