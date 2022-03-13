package main

import (
	"fmt"
	"log"
	"strings"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/go-routeros/routeros"
)

var addrList = make(map[string]string)

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(mikrotikHost, username, password, nil)
	}
	return routeros.Dial(mikrotikHost, username, password)
}

func initMikrotik() *routeros.Client {

	c, err := dial()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if async {
		c.Async()
	}

	initCmd := "/ip/firewall/address-list/print ?list=crowdsec =.proplist=.id,address"
	r, err := c.RunArgs(strings.Split(initCmd, " "))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("fill %d entry in internal addrList\n", len(r.Re))
	for _, v := range r.Re {
		addrList[v.Map["address"]] = v.Map[".id"]
	}

	return c
}

func decisionProcess(bouncer *csbouncer.StreamBouncer, c *routeros.Client) {

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
