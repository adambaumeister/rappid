package core

import (
	"encoding/xml"
	"fmt"
	"github.com/PaloAltoNetworks/pango"
	"net/url"
)

type Report struct {
	XMLName    xml.Name    `xml:"entry"`
	Period     string      `xml:"period"`
	TopN       int         `xml:"topn"`
	TopM       int         `xml:"topm"`
	Caption    string      `xml:"caption"`
	TrafficSum *TrafficSum `xml:"type>trsum"`
}

type TrafficSum struct {
	AggregateBy []string `xml:"aggregate-by>member"`
}

func AppReport(fw *pango.Firewall) error {
	params := url.Values{}
	params.Add("type", "report")
	params.Add("reportname", "api-dynamic")

	ts := TrafficSum{
		AggregateBy: []string{"app", "rule"},
	}

	report := Report{
		Period:     "last-7-days",
		TopN:       10,
		TopM:       10,
		Caption:    "TestAPIReport",
		TrafficSum: &ts,
	}

	reportSpec, err := xml.Marshal(report)

	params.Add("cmd", string(reportSpec))

	resp, err := fw.Communicate(params, nil)
	fmt.Printf(string(resp))
	return err
}
