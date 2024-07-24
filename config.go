package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

var (
	logLevel              string
	crowdsecBouncerAPIKey string
	crowdsecBouncerURL    string
	mikrotikHost          string
	username              string
	password              string
	async                 bool
	useTLS                bool
	useIPV6               bool
	crowdsecOrigins       []string
)

func initConfig() {
	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "1")
	viper.BindEnv("crowdsec_bouncer_api_key")
	viper.BindEnv("crowdsec_url")
	viper.SetDefault("crowdsec_url", "http://crowdsec:8080/")
	viper.BindEnv("mikrotik_host")
	viper.BindEnv("mikrotik_user")
	viper.BindEnv("mikrotik_pass")
	viper.BindEnv("mikrotik_tls")
	viper.SetDefault("mikrotik_tls", "true")
	viper.BindEnv("mikrotik_ipv6")
	viper.SetDefault("mikrotik_ipv6", "true")
	viper.BindEnv("crowdsec_origins")
	viper.SetDefault("crowdsec_origins", nil)

	logLevel = viper.GetString("log_level")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(level)

	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().Msg("Crowdsec API key is not set")
	}
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().Msg("Crowdsec URL is not set")
	}

	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	mikrotikHost = viper.GetString("mikrotik_host")

	username = viper.GetString("mikrotik_user")
	if username == "" {
		log.Fatal().Msg("Mikrotik username is not set")
	}

	password = viper.GetString("mikrotik_pass")
	if password == "" {
		log.Fatal().Msg("Mikrotik password is not set")
	}

	useTLS = viper.GetBool("mikrotik_tls")
	useIPV6 = viper.GetBool("mikrotik_ipv6")

	all := viper.AllSettings()
	delete(all, "mikrotik_pass")

	log.Printf("Using config: %+v", all)
}
