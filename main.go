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
			log.Fatalf("%s:%s [%s] openvpn-auth-azure-ad: %v",
				os.Getenv("untrusted_ip"),
				os.Getenv("untrusted_port"),
				os.Getenv("common_name"),
				err,
			)
		}

		os.Exit(openvpn.ExitCodeAuthPending)
	}
}

func startDeviceCodeAuthentication(conf config.Config) error {
	app, err := public.New(conf.AzureAd.ClientId, public.WithAuthority(conf.AzureAd.Authority))

	if err != nil {
		return fmt.Errorf("error while create new public client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(conf.AzureAd.Timeout)*time.Second)
	defer cancel()

	devCode, err := app.AcquireTokenByDeviceCode(ctx, conf.AzureAd.TokenScopes)

	if err != nil {
		return fmt.Errorf("error while acquireTokenByDeviceCode: %v", err)
	}

	fmt.Println(devCode.Result.UserCode)

	result, err := devCode.AuthenticationResult(ctx)
	if err != nil {
		return fmt.Errorf("error while getting AuthenticationResult: %v", err)
	}

	if conf.OpenVpn.MatchUsernameClientCn {
		commonName, ok := os.LookupEnv(openvpn.EnvVarCommonName)
		if !ok {
			return fmt.Errorf("can't find X509_0_CN environment variable")
		}

		field := reflect.Indirect(reflect.ValueOf(result.IDToken)).FieldByName(conf.OpenVpn.MatchUsernameTokenField)
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

	openUrl := fmt.Sprintf("%s%s?code=%s", openvpn.ExtraAuthPrefix[conf.OpenVpn.AuthMode], conf.OpenVpn.UrlHelper, deviceCode)
	openvpn.WriteAuthPending(conf.AzureAd.Timeout+5, conf.OpenVpn.AuthMode, openUrl)

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
