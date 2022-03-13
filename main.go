package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/go-routeros/routeros"
	"github.com/tuxtof/cs-mikrotik-bouncer/config"
)

var (
	// logLevel              = config.OptionalEnv("CROWDSEC_BOUNCER_LOG_LEVEL", "1")
	crowdsecBouncerApiKey = config.RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
	crowdsecBouncerUrl    = config.OptionalEnv("CROWDSEC_URL", "http://crowdsec:8080/")
	mikrotikHost          = config.RequiredEnv("MIKROTIK_HOST")
	username              = config.OptionalEnv("MIKROTIK_USER", "api")
	password              = config.OptionalEnv("MIKROTIK_PASS", "password")
	async                 = false
	useTLS                = false
)

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(mikrotikHost, username, password, nil)
	}
	return routeros.Dial(mikrotikHost, username, password)
}

func main() {

	flag.Parse()

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerApiKey,
		APIUrl:         crowdsecBouncerUrl,
		TickerInterval: "5s",
	}

	c, err := dial()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if async {
		c.Async()
	}

	addrList := make(map[string]string)

	initCmd := "/ip/firewall/address-list/print ?list=crowdsec =.proplist=.id,address"
	r, err := c.RunArgs(strings.Split(initCmd, " "))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("fill %d entry in internal addrList\n", len(r.Re))
	for _, v := range r.Re {
		addrList[v.Map["address"]] = v.Map[".id"]
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	for streamDecision := range bouncer.Stream {
		for _, decision := range streamDecision.Deleted {
			fmt.Printf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

			if addrList[*decision.Value] != "" {
				delCmd := fmt.Sprintf("/ip/firewall/address-list/remove =numbers=%s", addrList[*decision.Value])
				_, err := c.RunArgs(strings.Split(delCmd, " "))
				if err != nil {
					fmt.Println(err)
				}
				delete(addrList, *decision.Value)
				fmt.Printf("%s removed from mikrotik\n", *decision.Value)

			} else {
				fmt.Printf("%s not find in addrList\n", *decision.Value)
				// findCmd := fmt.Sprintf("/ip/firewall/address-list/print ?list=crowdsec ?address=%s =.proplist=.id", *decision.Value)
				// fmt.Printf("Search address %s in mikrotik ", *decision.Value)
				// r, err := c.RunArgs(strings.Split(findCmd, " "))
				// if err != nil {
				// 	fmt.Println(err)
				// }
				// if len(r.Re) > 0 {
				// 	fmt.Printf("found (%s)\n", r.Re[0].Map[".id"])
				// 	delCmd := fmt.Sprintf("/ip/firewall/address-list/remove =numbers=%s", r.Re[0].Map[".id"])
				// 	fmt.Printf("Delete address %s in mikrotik ", *decision.Value)
				// 	_, err := c.RunArgs(strings.Split(delCmd, " "))
				// 	if err != nil {
				// 		fmt.Println(err)
				// 	}
				// 	fmt.Println("done")
				// } else {
				// 	fmt.Println("not found")
				// }
			}

		}
		for _, decision := range streamDecision.New {
			fmt.Printf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v\n", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

			addCmd := fmt.Sprintf("/ip/firewall/address-list/add#=list=crowdsec#=address=%s#=comment=%s#=timeout=%s", *decision.Value, *decision.Scenario, *decision.Duration)

			if addrList[*decision.Value] != "" {
				fmt.Printf("Address %s already present\n", *decision.Value)
			} else {
				r, err := c.RunArgs(strings.Split(addCmd, "#"))
				if err != nil {
					fmt.Println(err)
				} else {
					addrList[*decision.Value] = r.Done.List[0].Value
					fmt.Printf("Address %s blocked in mikrotik\n", *decision.Value)
				}
			}
		}
	}
}
