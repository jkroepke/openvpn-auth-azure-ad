package openvpn

const (
	EnvVarCommonName       = "common_name"
	EnvVarAuthFailedReason = "auth_failed_reason_file"
	EnvVarAuthPending      = "auth_pending_file"
	EnvVarAuthControlFile  = "auth_control_file"
	EnvVarClientIp         = "untrusted_ip"
	EnvVarClientPort       = "untrusted_port"
	SupportedScriptType    = "user-pass-verify"

	ExitCodeAuthSuccess = 0
	ExitCodeAuthFailed  = 1
	ExitCodeAuthPending = 2

	ControlCodeAuthFailed  = 0
	ControlCodeAuthSuccess = 1
)

var ExtraAuthPrefix = map[string]string{
	"openurl": "OPEN_URL:",
	"webauth": "WEB_AUTH::",
}
