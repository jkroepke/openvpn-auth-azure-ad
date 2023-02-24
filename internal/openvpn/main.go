package openvpn

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

const (
	envVarAuthFailedReason = "auth_failed_reason_file"
	envVarAuthPending      = "auth_pending_file"
	envVarAuthControlFile  = "auth_control_file"
	supportedScriptType    = "user-pass-verify"

	ExitCodeAuthSuccess = 0
	ExitCodeAuthFailed  = 1
	ExitCodeAuthPending = 2

	ControlCodeAuthFailed  = 0
	ControlCodeAuthSuccess = 1
)

func CheckEnv() error {
	if os.Getenv("script_type") != supportedScriptType {
		return fmt.Errorf("only script_type %s is supported. got: %s", supportedScriptType, os.Getenv("script_type"))
	}

	if _, ok := os.LookupEnv(envVarAuthFailedReason); !ok {
		return fmt.Errorf("missing env variable %s", envVarAuthFailedReason)
	}

	if _, ok := os.LookupEnv(envVarAuthPending); !ok {
		return fmt.Errorf("missing env variable %s", envVarAuthPending)
	}

	if _, ok := os.LookupEnv(envVarAuthControlFile); !ok {
		return fmt.Errorf("missing env variable %s", envVarAuthControlFile)
	}

	return nil
}

func AuthFailedReason(reason string) {
	WriteAuthFailedReason(reason)
	WriteAuthControl(ControlCodeAuthFailed)
	log.Fatal(reason)
}

func WriteAuthFailedReason(reason string) {
	err := os.WriteFile(os.Getenv(envVarAuthFailedReason), []byte(reason), 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func WriteAuthControl(status int) {
	err := os.WriteFile(os.Getenv(envVarAuthControlFile), []byte(strconv.Itoa(status)), 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func WriteAuthPending(timeout int, method, extra string) {
	content := fmt.Sprintf("%d\n%s\n%s", timeout, method, extra)
	err := os.WriteFile(os.Getenv(envVarAuthPending), []byte(content), 0600)
	if err != nil {
		log.Fatal(err)
	}
}
