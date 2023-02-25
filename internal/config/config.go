package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AzureAd AzureAd `yaml:"azuread"`
	OpenVpn OpenVpn `yaml:"openvpn"`
}
type AzureAd struct {
	Authority   string   `yaml:"authority"`
	Timeout     int      `yaml:"timeout"`
	TokenScopes []string `yaml:"tokenScopes"`
	ClientId    string   `yaml:"clientId"`
}
type OpenVpn struct {
	AuthMode                string `yaml:"authMode"`
	UrlHelper               string `yaml:"urlHelper"`
	MatchUsernameClientCn   bool   `yaml:"matchUsernameClientCn"`
	MatchUsernameTokenField string `yaml:"matchUsernameTokenField"`
}

func LoadConfig(configFile string) (Config, error) {
	conf := Config{
		AzureAd: AzureAd{
			ClientId:    "",
			Timeout:     30,
			TokenScopes: []string{"user.read"},
			Authority:   "https://login.microsoftonline.com/organizations",
		},
		OpenVpn: OpenVpn{
			AuthMode:                "openurl",
			UrlHelper:               "https://jkroepke.github.io/openvpn-auth-azure-ad/",
			MatchUsernameClientCn:   true,
			MatchUsernameTokenField: "PreferredUsername",
		},
	}

	configFileContent, err := os.ReadFile(configFile)

	if err != nil {
		return conf, err
	}

	if err = yaml.Unmarshal(configFileContent, &conf); err != nil {
		return conf, err
	}

	if conf.AzureAd.ClientId == "" {
		return conf, fmt.Errorf("missing azuread.clientId")
	}

	if conf.OpenVpn.AuthMode != "openurl" && conf.OpenVpn.AuthMode != "webauth" {
		return conf, fmt.Errorf("openvpn.authMode must be 'openurl' or 'webauth'")
	}

	return conf, nil
}
