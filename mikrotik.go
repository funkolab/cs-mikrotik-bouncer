package main

import (
	"fmt"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog/log"

	"github.com/go-routeros/routeros"
)

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(mikrotikHost, username, password, nil)
	}
	return routeros.Dial(mikrotikHost, username, password)
}

func (mal *mikrotikAddrList) initMikrotik() {

	log.Info().Msg("Connecting to mikrotik")

	c, err := dial()
	if err != nil {
		log.Fatal().Err(err).Str("host", mikrotikHost).Str("username", username).Bool("useTLS", useTLS).Msg("Connection failed")
	}

	if async {
		c.Async()
	}

	mal.c = c

	mal.cache = make(map[string]string)

	protos := []string{"ip", "ipv6"}

	for _, proto := range protos {
		log.Info().Msgf("mikrotik %s list addr", proto)
		initCmd := fmt.Sprintf("/%s/firewall/address-list/print ?list=crowdsec =.proplist=.id,address", proto)
		r, err := c.RunArgs(strings.Split(initCmd, " "))
		if err != nil {
			log.Fatal().Err(err).Msg("address-list print failed")
		}
		log.Info().Msgf("fill %d entry in internal addrList\n", len(r.Re))
		for _, v := range r.Re {
			mal.cache[v.Map["address"]] = v.Map[".id"]
		}
	}
}

func (mal *mikrotikAddrList) add(decision *models.Decision) {

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	var proto string
	if strings.Contains(*decision.Value, ":") {
		proto = "ipv6"
	} else {
		proto = "ip"
	}

	var address string
	if *decision.Scope == "Ip" && proto == "ipv6" {
		address = fmt.Sprintf("%s/128", *decision.Value)
	} else {
		address = *decision.Value
	}

	addCmd := fmt.Sprintf("/%s/firewall/address-list/add#=list=crowdsec#=address=%s#=comment=%s#=timeout=%s", proto, address, *decision.Scenario, *decision.Duration)

	if mal.cache[address] != "" {
		log.Info().Msgf("Address %s already present", address)
	} else {

		r, err := mal.c.RunArgs(strings.Split(addCmd, "#"))
		log.Info().Msgf("resp %s", r)
		if err != nil {
			log.Error().Err(err).Msgf("%s address-list add cmd failed", proto)
		} else {
			mal.cache[address] = r.Done.List[0].Value
			log.Info().Msgf("Address %s blocked in mikrotik", address)
		}
	}
}

func (mal *mikrotikAddrList) remove(decision *models.Decision) {

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	var proto string
	if strings.Contains(*decision.Value, ":") {
		proto = "ipv6"
	} else {
		proto = "ip"
	}

	var address string
	if *decision.Scope == "Ip" && proto == "ipv6" {
		address = fmt.Sprintf("%s/128", *decision.Value)
	} else {
		address = *decision.Value
	}

	if mal.cache[address] != "" {

		log.Info().Msgf("Verify address %s in mikrotik", address)
		checkCmd := fmt.Sprintf("/%s/firewall/address-list/print =.proplist=address ?.id=%s", proto, mal.cache[address])
		r, err := mal.c.RunArgs(strings.Split(checkCmd, " "))
		if err != nil {
			log.Fatal().Err(err).Msgf("%s address-list search cmd failed", proto)
		}

		if len(r.Re) == 1 && r.Re[0].Map["address"] == address {
			delCmd := fmt.Sprintf("/%s/firewall/address-list/remove =numbers=%s", proto, mal.cache[address])
			_, err = mal.c.RunArgs(strings.Split(delCmd, " "))
			if err != nil {
				log.Error().Err(err).Msgf("%s address-list remove cmd failed", proto)
			}
			log.Info().Msgf("%s removed from mikrotik", address)
		} else {
			log.Info().Msgf("%s already removed from mikrotik", address)
		}
		delete(mal.cache, address)

	} else {
		log.Info().Msgf("%s not find in local cache", address)
	}
}

func (mal *mikrotikAddrList) decisionProcess(streamDecision *models.DecisionsStreamResponse) {

	for _, decision := range streamDecision.Deleted {
		mal.remove(decision)
	}
	for _, decision := range streamDecision.New {
		mal.add(decision)
	}
}
