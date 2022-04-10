package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func getStatus(cli *resty.Client) {
	trafficRules := &trafficRules{}
	cli.R().
		ForceContentType("application/json").
		SetResult(trafficRules).Get(viper.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules")
	for _, lib := range *trafficRules {
		fmt.Printf("name:%s action: %s enabled:%t\n", lib.Description, lib.Action, lib.Enabled)
	}
}

func auth(cli *resty.Client) *resty.Response {
	r, err := cli.R().
		SetHeader("Content-Type", "application/json").
		SetBody(`{"username":"` + viper.GetString(`unifi.username`) + `", "password":"` + viper.GetString(`unifi.password`) + `"}`).
		// SetResult(&AuthSuccess{}). // or SetResult(AuthSuccess{}).
		Post(viper.GetString(`unifi.baseURL`) + "/api/auth/login")
	if err != nil {
		panic(err)
	}

	for key, value := range r.Header() {
		if key == "X-Csrf-Token" {
			csrfHeader = value[0]
			// fmt.Println(key, "=", value)
			// fmt.Printf("Header set %s", csrfHeader)
			break
		}

	}
	return r
}

func init() {
	// Setup Client
	client = resty.New()
	// Standardize redirect policy
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))

	// JSON
	client.SetHeader("Accept", "application/json")
	client.SetHeader("Content-Type", "application/json")

	// Set the User-Agent header
	client.SetHeader("User-Agent", "dyer-test")

	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	auth(client)

}

// func SendRequest(payload []byte)
func sendRuleRequest(cli *resty.Client, payload []byte, isEnabled bool) {

	// if(method == "disable")
	r := &trafficRule{}
	err := json.Unmarshal(payload, &r)
	if err != nil {
		log.Errorf("Error in JSON unmarshalling from json marshalled object:", err)
		return
	}
	// fmt.Println("Before")
	b, _ := json.Marshal(r)
	r.Enabled = isEnabled
	// fmt.Printf("Enabled: %t \n", r.Enabled)
	// log.Errorf
	//
	log.WithFields(log.Fields{
		"ruleID":      r.ID,
		"Description": r.Description,
		"Enable":      isEnabled,
	}).Info("Making rule change")

	// fmt.Printf("===== Name: %s - Rule ID %s\n", r.Description, r.ID)
	// fmt.Println("======")
	// r.Enabled = true
	// fmt.Println("After")
	// fmt.Println(string(b))
	// fmt.Printf("Enabled: %t \n", r.Enabled)
	b, _ = json.Marshal(r)
	// fmt.Println(string(b))

	_, err = cli.R().
		SetBody(b).
		SetHeader("X-Csrf-Token", csrfHeader).
		SetHeader("accept", "application/json, text/plain, */*").
		SetHeader("content-type", "application/json").
		Put(viper.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules/" + r.ID)
	if err != nil {
		log.Error(err)
	}
}
