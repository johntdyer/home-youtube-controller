package main

/* cSpell:disable */

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v2" // imports as package "cli"

	// imports as package "cli"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/viper"

	"github.com/knadh/koanf"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

var (
	logger                                  *logrus.Entry
	client                                  *resty.Client
	authURL, username, password, csrfHeader string
	k                                       = koanf.New(".")
	ruleStatus                              *ruleChecker
)

// unifiYouTubeClient wraps resty.Client
type ruleChecker struct {
	resty                            *resty.Client
	config                           *viper.Viper
	allowRule                        *trafficRule
	denyRule                         *trafficRule
	denyRuleEnabled, allowRuleEnable bool
	csrfHeader                       string
}

func init() {
	viper.SetConfigName("config")         // name of config file (without extension)
	viper.SetConfigType("yaml")           // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("/etc/youtube/")  // path to look for the config file in
	viper.AddConfigPath("$HOME/.youtube") // call multiple times to add many search paths
	viper.AddConfigPath(".")              // optionally look for config in the working directory
	err := viper.ReadInConfig()           // Find and read the config file

	ruleStatus = &ruleChecker{
		resty:  resty.New(),
		config: viper.GetViper(),
	}

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)

	// Set log level
	level, err := logrus.ParseLevel(ruleStatus.config.GetString("logLevel"))
	if err != nil {
		log.Fatal(err)
	}
	logrus.SetLevel(level)

	// log.SetLevel(log.InfoLevel)
	logger = logrus.WithFields(log.Fields{
		"component": "cli-client",
	})

	ruleStatus.resty.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))
	ruleStatus.resty.SetHeader("Content-Type", "application/json")
	ruleStatus.resty.SetHeader("Accept", "application/json")
	ruleStatus.resty.SetHeader("User-Agent", "dyer-test")
	ruleStatus.setTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	ruleStatus.setup()

}

func (rc *ruleChecker) getCurrentStateJSON() (*currentStatus, []byte) {
	trafficRules := &trafficRules{}
	currentStatus := &currentStatus{}
	var jsonString []byte
	r, err := rc.resty.R().
		ForceContentType("application/json").
		SetResult(trafficRules).Get(ruleStatus.config.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules")
	if err != nil {
		log.Panic(err)
	}

	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		for _, lib := range *trafficRules {
			if rc.allowRule.ID == lib.ID {
				rc.allowRuleEnable = lib.Enabled
				currentStatus.AllowRuleEnabled = lib.Enabled
			} else if rc.denyRule.ID == lib.ID {
				rc.denyRuleEnabled = lib.Enabled
				currentStatus.BlockRuleEnabled = lib.Enabled
			}
		}
		jsonString, err = json.Marshal(currentStatus)

		if err != nil {
			fmt.Println("error:", err)
		}

	}
	return currentStatus, jsonString
}

func (rc *ruleChecker) getStatus() {
	trafficRules := &trafficRules{}
	r, err := rc.resty.R().
		ForceContentType("application/json").
		SetResult(trafficRules).Get(ruleStatus.config.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules")
	if err != nil {
		logger.Panic(err)
	}

	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		for _, lib := range *trafficRules {
			if rc.allowRule.ID == lib.ID {
				rc.allowRuleEnable = lib.Enabled
				logger.WithFields(log.Fields{"allowRuleEnable": lib.Enabled}).Debug("Allow Rule")
			} else if rc.denyRule.ID == lib.ID {
				rc.denyRuleEnabled = lib.Enabled
				logger.WithFields(log.Fields{"denyRuleEnabled": lib.Enabled}).Debug("Deny Rule")
			}

			logger.WithFields(log.Fields{
				"url":     r.Request.URL,
				"method":  r.Request.Method,
				"name":    lib.Description,
				"action":  lib.Action,
				"enabled": lib.Enabled,
			}).Debug("Found Rule")
		}
	}
}

func (rc *ruleChecker) setup() {
	r, err := rc.resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody(`{"username":"` + ruleStatus.config.GetString(`unifi.username`) + `", "password":"` + ruleStatus.config.GetString(`unifi.password`) + `"}`).
		Post(ruleStatus.config.GetString(`unifi.baseURL`) + "/api/auth/login")
	if err != nil {
		panic(err)
	}
	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		for key, value := range r.Header() {
			if key == "X-Csrf-Token" {
				rc.csrfHeader = value[0]
				break
			}

		}
		log.WithFields(log.Fields{
			"CSRFToken":    rc.csrfHeader,
			"responseCode": r.StatusCode(),
			"Set-Cookie":   r.Header()["Set-Cookie"],
		}).Debug("Authed")

		// Build Lists
		rc.buildRuleLists()
		// Set Status
		rc.getStatus()
	}
}

// SetTLSClientConfig assigns client TLS config
func (rc *ruleChecker) setTLSClientConfig(c *tls.Config) {
	rc.resty.SetTLSClientConfig(c)
}

func (rc *ruleChecker) toggleDenyRule() {

	rc.denyRule.Enabled = !rc.denyRuleEnabled

	r, err := rc.resty.R().
		SetBody(rc.denyRule).
		SetHeader("X-Csrf-Token", rc.csrfHeader).
		SetHeader("accept", "application/json, text/plain, */*").
		SetHeader("content-type", "application/json").
		Put(ruleStatus.config.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules/" + rc.denyRule.ID)
	if err != nil {
		log.Error(err)
	}
	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		logger.WithFields(log.Fields{
			"responseCode": r.StatusCode(),
			"method":       r.Request.Method,
			"url":          r.Request.URL,
		}).Debug("Deny rule changed")

	}
}

func (rc *ruleChecker) switchBlockRule(isEnabled bool) {

	rc.denyRule.Enabled = isEnabled

	r, err := rc.resty.R().
		SetBody(rc.denyRule).
		SetHeader("X-Csrf-Token", rc.csrfHeader).
		SetHeader("accept", "application/json, text/plain, */*").
		SetHeader("content-type", "application/json").
		Put(ruleStatus.config.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules/" + rc.denyRule.ID)
	if err != nil {
		log.Error(err)
	}
	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		logger.WithFields(log.Fields{
			"responseCode": r.StatusCode(),
			"method":       r.Request.Method,
			"url":          r.Request.URL,
		}).Debug("Deny rule changed")

	}
}

// Turn on allow Rule
func (rc *ruleChecker) switchAllowRule(isEnabled bool) {

	rc.allowRule.Enabled = isEnabled

	r, err := rc.resty.R().
		SetBody(rc.allowRule).
		SetHeader("X-Csrf-Token", rc.csrfHeader).
		SetHeader("accept", "application/json, text/plain, */*").
		SetHeader("content-type", "application/json").
		Put(ruleStatus.config.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules/" + rc.allowRule.ID)
	if err != nil {
		logger.Error(err)
	}
	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		logger.WithFields(log.Fields{
			"responseCode": r.StatusCode(),
			"method":       r.Request.Method,
			"url":          r.Request.URL,
		}).Debug("Allow rule changed")
	}

}

func (rc *ruleChecker) toggleAllowRule() {

	rc.allowRule.Enabled = !rc.allowRuleEnable

	r, err := rc.resty.R().
		SetBody(rc.allowRule).
		SetHeader("X-Csrf-Token", rc.csrfHeader).
		SetHeader("accept", "application/json, text/plain, */*").
		SetHeader("content-type", "application/json").
		Put(ruleStatus.config.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules/" + rc.allowRule.ID)
	if err != nil {
		log.Error(err)
	}
	if r.StatusCode() >= 400 {
		logger.WithFields(log.Fields{"response": string(r.Body()), "responseCode": r.StatusCode()}).Fatal("Error")
	} else {
		logger.WithFields(log.Fields{
			"responseCode": r.StatusCode(),
			"method":       r.Request.Method,
			"url":          r.Request.URL,
		}).Info("Allow rule changed")
	}

}

// Take mac addressses from config and build trafficRule to send to router
func (rc *ruleChecker) buildRuleLists() {

	rc.allowRule = &trafficRule{}
	rc.denyRule = &trafficRule{}

	if err := json.Unmarshal([]byte(ruleStatus.config.GetString("rules.allow_rule_scaffold")), &rc.allowRule); err != nil {
		logger.Errorf("Error in JSON unmarshalling from json marshalled object: %s", err)
		return
	}
	if err := json.Unmarshal([]byte(ruleStatus.config.GetString("rules.block_rule_scaffold")), &rc.denyRule); err != nil {
		logger.Errorf("Error in JSON unmarshalling from json marshalled object: %s", err)
		return
	}

	// Add whitelists from config to allowRule
	for _, lib := range ruleStatus.config.GetStringSlice("clients.whitelist") {
		i := &targetDevices{ClientMac: lib, Type: "CLIENT"}
		rc.allowRule.TargetDevices = append(rc.allowRule.TargetDevices, *i)

	}
}

func main() {

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "status",
				Aliases: []string{"s"},
				Usage:   "Get current status",
				Action: func(c *cli.Context) error {
					ruleStatus.getCurrentStateJSON()
					return nil
				},
			},
			{
				Name:  "allow",
				Usage: "Enable allow rule",
				Subcommands: []*cli.Command{
					{
						Name:     "on",
						Usage:    "enable allow rule",
						Category: "action",
						Action: func(c *cli.Context) error {
							ruleStatus.switchAllowRule(true)
							return nil
						},
					},
					{
						Name:     "off",
						Category: "action",
						Usage:    "disable allow rule",
						Action: func(c *cli.Context) error {
							ruleStatus.switchAllowRule(false)
							return nil
						},
					},
					{
						Name:    "toggle",
						Aliases: []string{"t"},

						Category: "action",
						Usage:    "togle allow rule",
						Action: func(c *cli.Context) error {
							ruleStatus.toggleAllowRule()
							return nil
						},
					},

					{
						Name:     "status",
						Usage:    "get status of allow rule",
						Aliases:  []string{"s"},
						Category: "action",
						Action: func(c *cli.Context) error {
							cs, _ := ruleStatus.getCurrentStateJSON()
							if cs.AllowRuleEnabled {
								fmt.Println("allow rule enabled")
								os.Exit(0)
							} else {
								fmt.Println("allow rule disabled")
								os.Exit(1)
							}
							return nil
						},
					},
				},
			},

			{
				Name:    "block",
				Aliases: []string{"B"},
				Usage:   "Enable block rule",
				Subcommands: []*cli.Command{
					{
						Name:     "on",
						Usage:    "enable block rule",
						Category: "action",
						Action: func(c *cli.Context) error {
							ruleStatus.switchBlockRule(true)
							return nil
						},
					},
					{
						Name:     "off",
						Usage:    "disable block rule",
						Category: "action",
						Action: func(c *cli.Context) error {
							ruleStatus.switchBlockRule(false)
							return nil
						},
					},
					{
						Name:     "status",
						Usage:    "get status of block rule",
						Category: "action",
						Action: func(c *cli.Context) error {

							cs, _ := ruleStatus.getCurrentStateJSON()
							if cs.BlockRuleEnabled {
								fmt.Println("block rule enabled")
								os.Exit(0)
							} else {
								fmt.Println("block rule disabled")
								os.Exit(1)
							}
							return nil
						},
					},
					{
						Name:     "toggle",
						Aliases:  []string{"t"},
						Category: "action",
						Usage:    "togle block rule",
						Action: func(c *cli.Context) error {
							ruleStatus.toggleDenyRule()
							return nil
						},
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	// app := &cli.App{
	// 	Name:     "youtube",
	// 	Version:  "v0.0.1",
	// 	Compiled: time.Now(),
	// 	Commands: []*cli.Command{
	// 		Name:    "allow",
	// 		Aliases: []string{"a"},
	// 		Usage:   "Allow Rule",
	// 		Subcommands: []*cli.Command{
	// 			{
	// 				Name:  "add",
	// 				Usage: "add a new template",
	// 				Action: func(c *cli.Context) error {
	// 					fmt.Println("new task template: ", c.Args().First())
	// 					return nil
	// 				},
	// 			},
	// 			{
	// 				Name:  "remove",
	// 				Usage: "remove an existing template",
	// 				Action: func(c *cli.Context) error {
	// 					fmt.Println("removed task template: ", c.Args().First())
	// 					return nil
	// 				},
	// 			},
	// 		},
	// 	},
	// }

	// var toggleAllow, toggleDeny, getState bool
	// flag.BoolVar(&toggleAllow, "toggle-allow", false, "toggle allow rule")
	// flag.BoolVar(&toggleDeny, "toggle-deny", false, "toggle deny rule")
	// flag.BoolVar(&toggleDeny, "toggle-deny", false, "toggle deny rule")
	// flag.BoolVar(&toggleDeny, "switch-deny", false, "toggle deny rule")
	// flag.BoolVar(&getState, "state", false, "Get current state")

	// flag.Parse()
	// if toggleAllow || toggleDeny {
	// 	if getState {
	// 		fmt.Println("state is mutually exclusive from toggle commands")
	// 		os.Exit(2)
	// 	}
	// }

	// if toggleAllow {
	// 	ruleStatus.toggleAllowRule()
	// }
	// if toggleDeny {
	// 	ruleStatus.toggleDenyRule()
	// }
	// if getState {
	// 	ruleStatus.getCurrentStateJSON()
	// }
	os.Exit(0)

	// fmt.Printf("ruleStatus.allowRuleEnable: %t | !ruleStatus.allowRuleEnable: %t \n", ruleStatus.denyRuleEnabled, !ruleStatus.allowRuleEnable)
	// fmt.Printf("ruleStatus.denyRuleEnabled: %t | !ruleStatus.denyRuleEnabled: %t \n", ruleStatus.denyRuleEnabled, !ruleStatus.denyRuleEnabled)
	fmt.Printf("ruleStatus.allowRule.Enabled: %t \n", ruleStatus.allowRule.Enabled)
	fmt.Printf("ruleStatus.denyRule.Enabled: %t \n", ruleStatus.denyRule.Enabled)

	// os.Exit(0)
	// logger.WithFields(log.Fields{"allowRuleEnabled": ruleStatus.allowRule.Enabled, "denyRuleEnabled": ruleStatus.denyRule.Enabled}).Info("beforeChange")
	ruleStatus.toggleDenyRule()
	ruleStatus.toggleAllowRule()
	fmt.Printf("ruleStatus.allowRule.Enabled: %t \n", ruleStatus.allowRule.Enabled)
	fmt.Printf("ruleStatus.denyRule.Enabled: %t \n", ruleStatus.denyRule.Enabled)
	// ruleStatus.toggleAllowRule()
	// logger.WithFields(log.Fields{"allowRuleEnabled": ruleStatus.allowRule.Enabled, "denyRuleEnabled": ruleStatus.denyRule.Enabled}).Info("afterChange")

	// ruleStatus.sendRuleRequest(allowJSON, true)
	// ruleStatus.sendRuleRequest(blockJSON, true) // trafficRules := &trafficRules{}
	// fmt.Println("after\n\n")
	// ruleStatus.GetStatus()
	// r, _ := ruleStatus.resty.R().
	// 	ForceContentType("application/json").
	// 	SetResult(trafficRules).Get(viper.GetString(`unifi.baseURL`) + "/proxy/network/v2/api/site/default/trafficrules")
	// for _, lib := range *trafficRules {

	// }

	// sendRuleRequest(client, allowJSON, false)
	// sendRuleRequest(client, blockJSON, false)
	// getStatus(client)

}
