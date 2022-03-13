package main

import (
	"github.com/rs/zerolog/log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {

	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	initConfig()

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: "5s",
	}
	if err := bouncer.Init(); err != nil {
		log.Fatal().Err(err)
	}

	c := initMikrotik()

	go bouncer.Run()

	decisionProcess(bouncer, c)

}
