package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/jkroepke/openvpn-auth-azure-ad/internal/config"
	"github.com/jkroepke/openvpn-auth-azure-ad/internal/openvpn"
)

const (
	envVarPendingAuth = "__OPENVPN_AUTH_AAD__START_PENDING_AUTH"
	envVarUserName    = "__OPENVPN_AUTH_AAD__USERNAME"
)

var version = "unknown"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		os.Exit(0)
	}

	if err := openvpn.CheckEnv(); err != nil {
		log.Fatalf(err.Error())
	}

	if len(os.Args) != 3 {
		log.Fatalf("Invalid count of CLI parameters. Usage: %s config-file credential-file", os.Args[0])
	}

	conf, err := config.LoadConfig(os.Args[1])
	if err != nil {
		log.Fatalf("Can't read config file: %v", err)
	}

	if _, ok := os.LookupEnv(envVarPendingAuth); ok {
		if err := startDeviceCodeAuthentication(conf); err != nil {
			openvpn.AuthFailedReason(err.Error())
		}
	} else {
		if err := startPendingAuthentication(conf); err != nil {
			log.Fatal(err.Error())
		}

		os.Exit(openvpn.ExitCodeAuthPending)
	}
}

func startDeviceCodeAuthentication(conf config.Config) error {
	username, ok := os.LookupEnv(envVarUserName)
	if !ok {
		return fmt.Errorf("can't find username environment variable")
	}

	app, err := public.New(conf.Azuread.ClientId, public.WithAuthority(conf.Azuread.Authority))

	if err != nil {
		return fmt.Errorf("error while create new public client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	devCode, err := app.AcquireTokenByDeviceCode(ctx, conf.Azuread.TokenScopes)

	if err != nil {
		return fmt.Errorf("error while acquireTokenByDeviceCode: %v", err)
	}

	fmt.Println(devCode.Result.UserCode)

	result, err := devCode.AuthenticationResult(ctx)
	if err != nil {
		return fmt.Errorf("error while getting AuthenticationResult: %v", err)
	}

	if conf.Openvpn.MatchUsername && username != "" && username != result.Account.PreferredUsername {
		return fmt.Errorf("vpn username does not match AD Username")
	}

	openvpn.WriteAuthControl(openvpn.ControlCodeAuthSuccess)

	return nil
}

func startPendingAuthentication(conf config.Config) error {
	credentialFile := os.Args[2]
	credentialFileContent, err := os.ReadFile(credentialFile)
	if err != nil {
		return fmt.Errorf("credential file does not accessable: %v", err)
	}

	username := strings.Split(string(credentialFileContent), "\n")[0]

	deviceCode, err := startDeviceCodeAuthProcess(username)

	if err != nil {
		return fmt.Errorf("error starting pending auth process: %v", err)
	}

	openUrl := fmt.Sprintf("OPENURL:%s?code=%s", conf.Openvpn.UrlHelper, deviceCode)
	openvpn.WriteAuthPending(100, "openurl", openUrl)

	return nil
}

func startDeviceCodeAuthProcess(username string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(cmd.Environ(), envVarPendingAuth+"=1", envVarUserName+"="+username)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Scan()
	deviceCode := scanner.Text()

	if strings.TrimSpace(deviceCode) == "" {
		return "", err
	}

	if err := stdout.Close(); err != nil {
		return "", err
	}

	return deviceCode, nil
}
