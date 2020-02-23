package core

import (
	"fmt"
	"github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/poli/security"
	"log"
	"strings"
)

type Logic struct {
	logger    *Logger
	firewalls []*pango.Firewall
	panoramas []*pango.Panorama
}

type Logger struct {
	Verbose bool
}

// Log a message to stdout.
// Optionally accept verbose as a bool value. Verbose will only be logged if set in the logger.
func (l *Logger) log(msg string, verbose bool) {
	if verbose == true {
		if l.Verbose == true {
			fmt.Printf("%s\n", msg)
		}
		return
	}
	fmt.Printf("%s\n", msg)
}

// Log a message to stderr.
// Optionally die after logging if specified.
func (l *Logger) checkError(e error, die bool) {
	if e != nil {
		if die == true {
			log.Fatal(e)
		}

		log.Print(e)
	}
}

// Initialize the main logic handler
func InitLogic(l *Logger) *Logic {
	cl := Logic{
		logger: l,
	}
	return &cl
}

// Add a device to the logic
// Uses type assertion to determine whether firewall or panorama
func (l *Logic) AddDevice(u string, p string, a string) {
	var err error
	c := pango.Client{
		Hostname: a,
		Username: u,
		Password: p,
		Logging:  pango.LogAction | pango.LogOp,
	}
	d, err := pango.Connect(c)
	l.logger.checkError(err, true)

	if v, ok := d.(*pango.Firewall); ok {
		l.logger.log(fmt.Sprintf("Added firewall %s\n", a), false)
		l.firewalls = append(l.firewalls, v)
	}

	if v, ok := d.(*pango.Panorama); ok {
		l.panoramas = append(l.panoramas, v)
	}
}

/*
ConvertRuleNames does an appid conversion "in place" given a list of rule names.
*/
func (l *Logic) ConvertRuleNames(ruleNames []string, dg string, vsys string) {
	for _, rn := range ruleNames {
		l.logger.log(fmt.Sprintf("Finding %s..", rn), true)
		var entries []security.Entry

		for _, fw := range l.firewalls {
			l.getAllFwPolicies(fw)
		}

		for _, p := range l.panoramas {
			l.logger.log(fmt.Sprintf("Searching dg %s", dg), true)
			entries = l.getAllPanPolicies(p, dg)
		}

		l.findServiceRules(entries)
	}
}

// Retrieves all of the policy objects at the given vsys in a firewall
func (l *Logic) getAllFwPolicies(fw *pango.Firewall) {
	entries, err := fw.Policies.Security.GetAll("vsys1")
	l.logger.checkError(err, true)
	l.logger.log(fmt.Sprintf("Found %s firewall rules", len(entries)), true)
}

// Retrieves all of the policy objects at the given DG in Panorama
func (l *Logic) getAllPanPolicies(p *pango.Panorama, dg string) []security.Entry {
	entries, err := p.Policies.Security.GetAll(dg, "")
	l.logger.checkError(err, true)
	l.logger.log(fmt.Sprintf("Found %s firewall rules", len(entries)), true)
	return entries
}

func (l *Logic) findServiceRules(e []security.Entry) {
	for _, entry := range e {
		l.logger.log(fmt.Sprintf("Checking %s %s %s", entry.Name, strings.Join(entry.Services, " - "), strings.Join(entry.Applications, " - ")), true)
	}
}
