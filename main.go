package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"

	"golang.org/x/exp/slices"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/jkroepke/openvpn-auth-azure-ad/internal/config"
	"github.com/jkroepke/openvpn-auth-azure-ad/internal/openvpn"
)

const (
	envVarPendingAuth = "__OPENVPN_AUTH_AAD__START_PENDING_AUTH"
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

	if len(os.Args) != 2 {
		log.Fatalf("Invalid count of CLI parameters. Usage: %s credential-file", os.Args[0])
	}

	conf, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Can't read config: %v", err)
	}

	if commonName, ok := os.LookupEnv(openvpn.EnvVarCommonName); ok && slices.Contains(conf.AzureAdOpenVpnCnBypassAzureAd, commonName) {
		log.Printf("%s:%s [%s] openvpn-auth-azure-ad: %v",
			os.Getenv(openvpn.EnvVarClientIp),
			os.Getenv(openvpn.EnvVarClientPort),
			os.Getenv(openvpn.EnvVarCommonName),
			"skip azure ad authentification",
		)
	}

	if _, ok := os.LookupEnv(envVarPendingAuth); ok {
		if err := startDeviceCodeAuthentication(conf); err != nil {
			openvpn.AuthFailedReason(err.Error())
		}
	} else {
		if err := startPendingAuthentication(conf); err != nil {
			log.Fatalf("%s:%s [%s] openvpn-auth-azure-ad: %v",
				os.Getenv(openvpn.EnvVarClientIp),
				os.Getenv(openvpn.EnvVarClientPort),
				os.Getenv(openvpn.EnvVarCommonName),
				err,
			)
		}

		os.Exit(openvpn.ExitCodeAuthPending)
	}
}

func startDeviceCodeAuthentication(conf config.Config) error {
	app, err := public.New(conf.AzureAdClientId, public.WithAuthority(conf.AzureAdAuthority))

	if err != nil {
		return fmt.Errorf("error while create new public client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.AzureAdTimeout)*time.Second)
	defer cancel()

	devCode, err := app.AcquireTokenByDeviceCode(ctx, conf.AzureAdTokenScopes)

	if err != nil {
		return fmt.Errorf("error while acquireTokenByDeviceCode: %v", err)
	}

	fmt.Println(devCode.Result.UserCode)

	result, err := devCode.AuthenticationResult(ctx)
	if err != nil {
		return fmt.Errorf("error while getting AuthenticationResult: %v", err)
	}

	if conf.AzureAdOpenVpnMatchUsernameClientCn {
		commonName, ok := os.LookupEnv(openvpn.EnvVarCommonName)
		if !ok {
			return fmt.Errorf("can't find X509_0_CN environment variable")
		}

		field := reflect.Indirect(reflect.ValueOf(result.IDToken)).FieldByName(conf.AzureAdOpenVpnMatchUsernameTokenField)
		if commonName != field.String() {
			return fmt.Errorf("client common_name does not match AD Username")
		}
	}

	openvpn.WriteAuthControl(openvpn.ControlCodeAuthSuccess)

	return nil
}

func startPendingAuthentication(conf config.Config) error {
	deviceCode, err := startDeviceCodeAuthProcess()

	if err != nil {
		return fmt.Errorf("error starting pending auth process: %v", err)
	}

	if ivSso, ok := os.LookupEnv(openvpn.IvSso); !ok {
		return fmt.Errorf("can't find IV_SSO environment variable. Client doesn't support SSO login")
	} else if !strings.Contains(ivSso, "webauth") {
		return fmt.Errorf("client doesn't support 'webauth'")
	}

	openUrl := fmt.Sprintf("WEB_AUTH::%s?code=%s", conf.AzureAdOpenVpnUrlHelper.String(), deviceCode)
	err = openvpn.WriteAuthPending(conf.AzureAdTimeout, "webauth", openUrl)

	if err != nil {
		return fmt.Errorf("error writing content to auth pending file: %v", err)
	}

	return nil
}

func startDeviceCodeAuthProcess() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(cmd.Environ(), envVarPendingAuth+"=1")
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
