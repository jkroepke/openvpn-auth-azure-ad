package config

import (
	"github.com/caarlos0/env/v7"
	"net/url"
)

type Config struct {
	AzureAdAuthority                      string   `env:"AZURE_AD_AUTHORITY" envDefault:"https://login.microsoftonline.com/${AZURE_AD_TENANT_ID}" envExpand:"true"`
	AzureAdTimeout                        int      `env:"AZURE_AD_TIMEOUT" envDefault:"300"`
	AzureAdTenantId                       string   `env:"AZURE_AD_TENANT_ID"`
	AzureAdClientId                       string   `env:"AZURE_AD_CLIENT_ID"`
	AzureAdTokenScopes                    []string `env:"AZURE_AD_TOKEN_SCOPES" envDefault:"" envSeparator:" "`
	AzureAdOpenVpnUrlHelper               url.URL  `env:"AZURE_AD_OPENVPN_URL_HELPER" envDefault:"https://jkroepke.github.io/openvpn-auth-azure-ad/"`
	AzureAdOpenVpnMatchUsernameClientCn   bool     `env:"AZURE_AD_OPENVPN_MATCH_USERNAME_CLIENT_CN" envDefault:"true"`
	AzureAdOpenVpnMatchUsernameTokenField string   `env:"AZURE_AD_OPENVPN_MATCH_USERNAME_TOKEN_FIELD" envDefault:"PreferredUsername"`
	AzureAdOpenVpnMatchClientIp           bool     `env:"AZURE_AD_OPENVPN_MATCH_CLIENT_IP" envDefault:"true"`
	AzureAdOpenVpnCnBypassAzureAd         []string `env:"AZURE_AD_OPENVPN_CN_BYPASS_AZURE_AD" envDefault:"" envSeparator:","`
}

func LoadConfig() (Config, error) {
	conf := Config{}
	opts := env.Options{RequiredIfNoDef: true}

	// Load env vars.
	if err := env.Parse(&conf, opts); err != nil {
		return conf, err
	}

	return conf, nil
}
