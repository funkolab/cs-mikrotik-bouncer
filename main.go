package main

import (
	"log"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func main() {

	initConfig()

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: "5s",
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	c := initMikrotik()

	go bouncer.Run()

	decisionProcess(bouncer, c)

}
