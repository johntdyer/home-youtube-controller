package main

/* cSpell:disable */

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

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

func init() {
	viper.SetConfigName("youtube-controller") // name of config file (without extension)
	viper.SetConfigType("yaml")               // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("/config/")           // path to look for the config file in
	viper.AddConfigPath("/etc/youtube/")      // path to look for the config file in
	viper.AddConfigPath("$HOME/.youtube")     // call multiple times to add many search paths
	viper.AddConfigPath(".")                  // optionally look for config in the working directory
	err := viper.ReadInConfig()               // Find and read the config file

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

func main() {

	app := &cli.App{
		Version:  "v0.0.1",
		Compiled: time.Now(),
		Commands: []*cli.Command{
			{
				Name:    "status",
				Aliases: []string{"s"},
				Usage:   "Get current status",
				Action: func(c *cli.Context) error {
					_, status := ruleStatus.getCurrentStateJSON()
					fmt.Println(string(status))
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
	os.Exit(0)

}
