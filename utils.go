package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func (rc *ruleChecker) getCurrentStateJSON() (*currentStatus, []byte) {
	trafficRules := &trafficRules{}
	currentStatus := &currentStatus{}
	var jsonString []byte
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
