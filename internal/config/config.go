package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Azuread AzureAd `yaml:"azuread"`
	Openvpn OpenVpn `yaml:"openvpn"`
}
type AzureAd struct {
	Authority   string   `yaml:"authority"`
	TokenScopes []string `yaml:"tokenScopes"`
	ClientId    string   `yaml:"clientId"`
}
type OpenVpn struct {
	UrlHelper     string `yaml:"urlHelper"`
	MatchUsername bool   `yaml:"matchUsername"`
}

func LoadConfig(configFile string) (Config, error) {
	config := Config{
		Azuread: AzureAd{
			ClientId:    "",
			TokenScopes: []string{"user.read"},
			Authority:   "https://login.microsoftonline.com/organizations",
		},
		Openvpn: OpenVpn{
			UrlHelper:     "https://jkroepke.github.io/openvpn-auth-azure-ad/",
			MatchUsername: true,
		},
	}

	configFileContent, err := os.ReadFile(configFile)

	if err != nil {
		return config, err
	}

	if err = yaml.Unmarshal(configFileContent, &config); err != nil {
		return config, err
	}

	if config.Azuread.ClientId == "" {
		return config, fmt.Errorf("missing azuread.clientId")
	}

	return config, nil
}
