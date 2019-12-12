package sdk

type PasswordRuleMatcher interface {
	GetRuleIntro() string
	MatchFailedRules(password string) []string
}

type TwoFactorChannel int
const (
	Authenticator TwoFactorChannel = iota
	TextMessage
	DuoSecurity
	Other
)
func (channel TwoFactorChannel) String() string {
	return [...]string {"Authenticator", "TextMessage", "DuoSecurity", "Other"}[channel]
}

type TwoFactorCodeDuration int32
const (
	EveryLogin TwoFactorCodeDuration = 0
    Every30Days = 30
    Forever = 99999
)
func (duration TwoFactorCodeDuration) String() string {
	switch duration {
	case EveryLogin:
		return "every_login"
	case Every30Days:
		return "every_30_days"
	case Forever:
		return "forever"
	}
	return "every_login"
}

type AuthUI interface {
	Confirmation(information string) bool
	GetNewPassword(matcher PasswordRuleMatcher) string
	GetTwoFactorCode(channel TwoFactorChannel) (string, TwoFactorCodeDuration)
}
