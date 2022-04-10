package main

type trafficRule struct {
	ID             string          `json:"_id"`
	Action         string          `json:"action"`
	AppCategoryIds []string        `default:"[]" json:"app_category_ids"`
	AppIds         []int           `default:"[]" json:"app_ids"`
	Description    string          `json:"description"`
	Domains        []string        `default:"[]" json:"domains"`
	Enabled        bool            `json:"enabled"`
	IPAddresses    []string        `default:"[]" json:"ip_addresses"`
	IPRanges       []string        `default:"[]" json:"ip_ranges"`
	MatchingTarget string          `default:"APP" json:"matching_target"`
	NetworkIds     []string        `default:"[]" json:"network_ids"`
	Schedule       schedule        `json:"schedule"`
	TargetDevices  []targetDevices `json:"target_devices" default:"[{\"type\": \"ALL_CLIENTS\"}]"`
}

type currentStatus struct {
	AllowRuleEnabled bool `json:"allow_rule_enabled"`
	BlockRuleEnabled bool `json:"block_rule_enabled"`
}
type targetDevices struct {
	ClientMac string `json:"client_mac,omitempty"`
	Type      string `json:"type" default:"CLIENT"`
}
type schedule struct {
	DateEnd        string   `json:"date_end" default:"2035-03-09"`
	DateStart      string   `json:"date_start" default:"2022-03-09"`
	Mode           string   `json:"mode" default:"ALWAYS"`
	RepeatOnDays   []string `json:"repeat_on_days" default:"[]"`
	TimeAllDay     bool     `json:"time_all_day"`
	TimeRangeEnd   string   `json:"time_range_end" default:"12:00"`
	TimeRangeStart string   `json:"time_range_start" default:"09:00"`
}

// TrafficRules - blah
type trafficRules []struct {
	ID             string        `json:"_id"`
	Action         string        `json:"action"`
	AppCategoryIds []interface{} `json:"app_category_ids"`
	AppIds         []int         `json:"app_ids"`
	Description    string        `json:"description"`
	Domains        []interface{} `json:"domains"`
	Enabled        bool          `json:"enabled"`
	IPAddresses    []interface{} `json:"ip_addresses"`
	IPRanges       []interface{} `json:"ip_ranges"`
	MatchingTarget string        `json:"matching_target"`
	NetworkIds     []interface{} `json:"network_ids"`
	Schedule       struct {
		DateEnd        string        `json:"date_end"`
		DateStart      string        `json:"date_start"`
		Mode           string        `json:"mode"`
		RepeatOnDays   []interface{} `json:"repeat_on_days"`
		TimeAllDay     bool          `json:"time_all_day"`
		TimeRangeEnd   string        `json:"time_range_end"`
		TimeRangeStart string        `json:"time_range_start"`
	} `json:"schedule"`
	TargetDevices []struct {
		Type string `json:"type"`
	} `json:"target_devices"`
}
