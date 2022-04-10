package main

import (
	"fmt"

	"github.com/go-routeros/routeros"
	"github.com/rs/zerolog/log"
	"gopkg.in/tomb.v2"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

var t tomb.Tomb

type mikrotikAddrList struct {
	c     *routeros.Client
	cache map[string]string
}

func main() {

	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	initConfig()

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: "5s",
	}
	if err := bouncer.Init(); err != nil {
		log.Fatal().Err(err).Msg("Bouncer init failed")
	}

	var mal mikrotikAddrList

	mal.initMikrotik()
	defer mal.c.Close()

	t.Go(func() error {
		bouncer.Run()
		return fmt.Errorf("stream api init failed")
	})

	t.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-t.Dying():
				log.Error().Msg("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				mal.decisionProcess(decisions)
			}
		}
	})

	err := t.Wait()

	if err != nil {
		log.Error().Err(err).Send()
	}

}
