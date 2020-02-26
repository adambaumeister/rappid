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

type ReportJobResult struct {
	Status string `xml:"status,attr"`
	JobID  string `xml:"result>job"`
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

	if err != nil {
		return err
	}
	params.Add("cmd", string(reportSpec))

	rjr := ReportJobResult{}
	resp, err := fw.Communicate(params, &rjr)

	jobParams := url.Values{}
	fmt.Printf("Jobid: %s %s\n", string(rjr.JobID), string(resp))
	jobParams.Add("type", "report")
	jobParams.Add("action", "get")
	jobParams.Add("job-id", rjr.JobID)
	resp, err = fw.Communicate(jobParams, nil)

	fmt.Printf(string(resp))
	return err
}
