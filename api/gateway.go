package api

import (
	"encoding/json"
	"fmt"
	"strconv"
)

type GatewayService service

type IGatewayService interface {
	Get(name string) (*Gateway, *Response, error)
	List() ([]*Gateway, *Response, error)
	Update(gw *Gateway) (*Gateway, *Response, error)
}

type Gateway struct {
	Name         string                 `json:"name,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
	Selector     string                 `json:"selector,omitempty"`
	VirtualHosts []string               `json:"virtual_hosts"`
	Routes       map[string]Route       `json:"routes"`

	Kind       string `json:"kind"`
	Port       string `json:"port"`
	Sticky     string `json:"sticky,omitempty"`
	Internal   bool   `json:"internal"`
	Deployed   bool   `json:"deployed"`
	LookupName string `json:"lookup_name"`
	Service    struct {
		Host string `json:"host"`
		Port string `json:"port"`
	} `json:"service"`
}

type Route struct {
	LookupName string                 `json:"lookup_name"`
	Metadata   map[string]interface{} `json:"metadata"`
	Balance    string                 `json:"balance"`
	Rewrites   []struct {
		Path string `json:"path"`
	} `json:"rewrites"`
	Weight            int    `json:"-"`
	Condition         string `json:"-"`
	ConditionStrength int    `json:"-"`
}

func (r Route) MarshalJSON() ([]byte, error) {
	type Alias Route
	return json.Marshal(&struct {
		WeightRaw            string `json:"weight"`
		ConditionRaw         string `json:"condition"`
		ConditionStrengthRaw string `json:"condition_strength"`
		Alias
	}{
		ConditionRaw:         r.Condition,
		WeightRaw:            fmt.Sprintf("%d%%", r.Weight),
		ConditionStrengthRaw: fmt.Sprintf("%d%%", r.ConditionStrength),
		Alias:                (Alias)(r),
	})
}

func (r *Route) UnmarshalJSON(data []byte) error {
	type Alias Route
	aux := &struct {
		WeightRaw            string            `json:"weight"`
		ConditionRaw         map[string]string `json:"condition"`
		ConditionStrengthRaw string            `json:"condition_strength"`
		Alias
	}{
		Alias: (Alias)(*r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.ConditionRaw != nil {
		r.Condition = aux.ConditionRaw["condition"]
	}
	r.Weight, _ = strconv.Atoi(aux.WeightRaw[:len(aux.WeightRaw)-1])
	r.ConditionStrength, _ = strconv.Atoi(aux.ConditionStrengthRaw[:len(aux.ConditionStrengthRaw)-1])
	return nil
}

func (s *GatewayService) Get(name string) (*Gateway, *Response, error) {
	u := fmt.Sprintf("gateways/%s", name)
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	gateway := new(Gateway)
	response, err := s.client.Do(req, gateway)
	if err != nil {
		return nil, response, err
	}
	return gateway, response, nil
}

func (s *GatewayService) Update(gw *Gateway) (*Gateway, *Response, error) {
	u := fmt.Sprintf("gateways/%s", gw.Name)
	req, err := s.client.NewRequest("PUT", u, gw)
	if err != nil {
		return nil, nil, err
	}

	gateway := new(Gateway)
	response, err := s.client.Do(req, gateway)
	if err != nil {
		return nil, response, err
	}
	return gateway, response, nil
}

func (s *GatewayService) List() ([]*Gateway, *Response, error) {
	u := fmt.Sprintf("gateways")
	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var gateways []*Gateway
	response, err := s.client.Do(req, &gateways)
	if err != nil {
		return nil, response, err
	}
	return gateways, response, nil
}
