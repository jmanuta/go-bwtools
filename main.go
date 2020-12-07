package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stretchr/objx"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

type request struct {
	xmlheader  string
	xmlfooter  string
	message    string
	soapheader string
	soapfooter string
}

type client struct {
	username   string
	password   string
	baseURL    string
	sessionID  string
	jsessionID string
	nonce      string
	hash       string
}

// Config file setup
type Config struct {
	Production struct {
		URL      string `yaml:"url"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"production"`
	Lab struct {
		URL      string `yaml:"url"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"lab"`
}

// SendRequest to OCI-P Interface
func (c *client) sendRequest(message string) ([]byte, int) {

	r := request{
		xmlheader:  `<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:com:broadsoft:webservice"><SOAP-ENV:Body><ns1:processOCIMessage><ns1:in0>`,
		soapheader: fmt.Sprintf(`&lt;?xml version=&#34;1.0&#34; encoding="UTF-8"?&gt;&lt;BroadsoftDocument protocol="OCI" xmlns=&quot;C&quot; xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"&gt;&lt;sessionId xmlns=""&gt;%v&lt;/sessionId&gt;`, c.sessionID),
		message:    message,
		soapfooter: `&lt;/BroadsoftDocument&gt;`,
		xmlfooter:  `</ns1:in0></ns1:processOCIMessage></SOAP-ENV:Body></SOAP-ENV:Envelope>`,
	}

	// Create http client
	client := &http.Client{Timeout: 3 * time.Second}

	// Format the POST request, set the URL and convert the request to bytes
	req, err := http.NewRequest("POST", c.baseURL, bytes.NewReader([]byte(fmt.Sprintf("%s%s%s%s%s", r.xmlheader, r.soapheader, r.message, r.soapfooter, r.xmlfooter))))
	if err != nil {
		panic(err)
	}

	// Set headers for SOAP
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `""`)
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Accept", "*/*")

	// Add cookie if present
	if c.jsessionID != "" {
		req.Header.Set("Cookie", c.jsessionID)
	}

	// Execute the POST and store response, check for errors
	response, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// Extract and store jsessionId
	if c.jsessionID == "" {
		cookie := response.Header["Set-Cookie"][0]
		cookieparse := strings.Fields(cookie)
		c.jsessionID = cookieparse[0]
	}

	// Close
	defer response.Body.Close()

	// Store the body of the response in byte[]
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	return body, response.StatusCode

}

func loadConfig(f string) *Config {

	// Create empty struct to hold data
	config := &Config{}

	// Read the specified file
	file, err := os.Open(f)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Decode the file as yaml and Unmarshal to config struct
	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		log.Fatal(err)
	}

	// Return the struct
	return config
}

func main() {

	// Removes timestamp from error output
	log.SetFlags(0)

	// Load config file
	config := loadConfig("config.yml")

	app := &cli.App{
		Name:    "BWTools",
		Version: "v1.2.0",
		Usage:   "Broadworks OCI-P Testing",
		Authors: []*cli.Author{
			&cli.Author{
				Email: "jmanuta@bluip.com",
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "lab",
				Aliases: []string{"l"},
				Usage:   "send request to lab broadworks",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "call-limits",
				Usage: "list call limit settings for each user in a group",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "enterprise",
						Aliases:  []string{"e"},
						Usage:    "enterprise ID",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "group",
						Aliases:  []string{"g"},
						Usage:    "group ID",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "header",
						Usage: "show column headers",
					},
					&cli.BoolFlag{
						Name:    "include",
						Aliases: []string{"i"},
						Usage:   "include enterprise and group profile in the list",
					},
				},
				Action: func(c *cli.Context) error {

					// Generate a pseudo random sessionID
					SID := func() string {
						l := 20 // length
						buff := make([]byte, int(math.Round(float64(l)/float64(1.33333333333))))
						rand.Read(buff)
						str := base64.RawURLEncoding.EncodeToString(buff)
						return str[:l] // strip 1 extra character we get from odd length results
					}()

					// Create an instance of client
					cl := &client{
						username:  config.Production.Username,
						password:  config.Production.Password,
						baseURL:   config.Production.URL,
						sessionID: SID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: SID,
						}
					}

					// Authenticate and login
					err := cl.authenticationRequest()
					if err != nil {
						log.Fatal(err)
					}

					// Login
					err = cl.loginRequest14sp4()
					if err != nil {
						log.Fatal(err)
					}

					// Build a user list from the specified enterprise and group
					users := cl.UserGetListInGroupRequest(c.String("enterprise"), c.String("group"))

					// Print header if flagged
					if c.Bool("header") {
						fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
							"userId",
							"useUserCallLimitsSetting",
							"useMaxSimultaneousCalls",
							"maxSimultaneousCalls",
							"useMaxSimultaneousVideoCalls",
							"maxSimultaneousVideoCalls",
							"useMaxCallTimeForAnsweredCalls",
							"maxCallTimeForAnsweredCallsMinutes",
							"useMaxCallTimeForUnansweredCalls",
							"maxCallTimeForUnansweredCallsMinutes",
							"useMaxConcurrentRedirectedCalls",
							"maxConcurrentRedirectedCalls",
							"useMaxFindMeFollowMeDepth",
							"maxFindMeFollowMeDepth",
							"maxRedirectionDepth",
							"useMaxConcurrentFindMeFollowMeInvocations",
							"maxConcurrentFindMeFollowMeInvocations",
						)
					}

					// Iterate through user list and retrieve the CP Policy for each
					for i := 0; i < len(users); i++ {

						userProfile := cl.userCallProcessingGetPolicyRequest21Sp1(users[i])

						fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
							users[i],
							userProfile["UseUserCallLimitsSetting"],
							userProfile["UseMaxSimultaneousCalls"],
							userProfile["MaxSimultaneousCalls"],
							userProfile["UseMaxSimultaneousVideoCalls"],
							userProfile["MaxSimultaneousVideoCalls"],
							userProfile["UseMaxCallTimeForAnsweredCalls"],
							userProfile["MaxCallTimeForAnsweredCallsMinutes"],
							userProfile["UseMaxCallTimeForUnansweredCalls"],
							userProfile["MaxCallTimeForUnansweredCallsMinutes"],
							userProfile["UseMaxConcurrentRedirectedCalls"],
							userProfile["MaxConcurrentRedirectedCalls"],
							userProfile["UseMaxConcurrentFindMeFollowMeInvocations"],
							userProfile["MaxConcurrentFindMeFollowMeInvocations"],
							userProfile["UseMaxFindMeFollowMeDepth"],
							userProfile["MaxFindMeFollowMeDepth"],
							userProfile["MaxRedirectionDepth"],
						)

					}

					if c.Bool("include") {
						if c.Bool("header") {
							fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
								"enterprise",
								"useMaxSimultaneousCalls",
								"maxSimultaneousCalls",
								"useMaxSimultaneousVideoCalls",
								"maxSimultaneousVideoCalls",
								"useMaxCallTimeForAnsweredCalls",
								"maxCallTimeForAnsweredCallsMinutes",
								"useMaxCallTimeForUnansweredCalls",
								"maxCallTimeForUnansweredCallsMinutes",
								"useMaxConcurrentRedirectedCalls",
								"maxConcurrentRedirectedCalls",
								"useMaxFindMeFollowMeDepth",
								"maxFindMeFollowMeDepth",
								"maxRedirectionDepth",
								"useMaxConcurrentFindMeFollowMeInvocations",
								"maxConcurrentFindMeFollowMeInvocations",
							)
						}
						entProfile := cl.serviceProviderCallProcessingGetPolicyRequest21Sp1(c.String("enterprise"))
						fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
							c.String("enterprise"),
							entProfile["UseMaxSimultaneousCalls"],
							entProfile["MaxSimultaneousCalls"],
							entProfile["UseMaxSimultaneousVideoCalls"],
							entProfile["MaxSimultaneousVideoCalls"],
							entProfile["UseMaxCallTimeForAnsweredCalls"],
							entProfile["MaxCallTimeForAnsweredCallsMinutes"],
							entProfile["UseMaxCallTimeForUnansweredCall"],
							entProfile["MaxCallTimeForUnansweredCallsMinutes"],
							entProfile["UseMaxConcurrentRedirectedCalls"],
							entProfile["MaxConcurrentRedirectedCalls"],
							entProfile["UseMaxConcurrentFindMeFollowMeInvocations"],
							entProfile["MaxConcurrentFindMeFollowMeInvocations"],
							entProfile["UseMaxFindMeFollowMeDepth"],
							entProfile["MaxFindMeFollowMeDepth"],
							entProfile["MaxRedirectionDepth"],
						)

						//fmt.Print(cl.serviceProviderCallProcessingGetPolicyRequest21Sp1(c.String("enterprise")))
						if c.Bool("header") {
							fmt.Printf("%v-%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
								"enterprise",
								"group",
								"useUserGroupLimitsSetting",
								"useMaxSimultaneousCalls",
								"maxSimultaneousCalls",
								"useMaxSimultaneousVideoCalls",
								"maxSimultaneousVideoCalls",
								"useMaxCallTimeForAnsweredCalls",
								"maxCallTimeForAnsweredCallsMinutes",
								"useMaxCallTimeForUnansweredCalls",
								"maxCallTimeForUnansweredCallsMinutes",
								"useMaxConcurrentRedirectedCalls",
								"maxConcurrentRedirectedCalls",
								"useMaxFindMeFollowMeDepth",
								"maxFindMeFollowMeDepth",
								"maxRedirectionDepth",
								"useMaxConcurrentFindMeFollowMeInvocations",
								"maxConcurrentFindMeFollowMeInvocations",
							)
						}
						groupProfile := cl.groupCallProcessingGetPolicyRequest21Sp1(c.String("enterprise"), c.String("group"))
						fmt.Printf("%v-%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
							c.String("enterprise"),
							c.String("group"),
							groupProfile["UseGroupCallLimitsSetting"],
							groupProfile["UseMaxSimultaneousCall"],
							groupProfile["MaxSimultaneousCalls"],
							groupProfile["UseMaxSimultaneousVideoCalls"],
							groupProfile["MaxSimultaneousVideoCalls"],
							groupProfile["UseMaxCallTimeForAnsweredCall"],
							groupProfile["MaxCallTimeForAnsweredCallsMinutes"],
							groupProfile["UseMaxCallTimeForUnansweredCalls"],
							groupProfile["MaxCallTimeForUnansweredCallsMinute"],
							groupProfile["UseMaxConcurrentRedirectedCalls"],
							groupProfile["MaxConcurrentRedirectedCalls"],
							groupProfile["UseMaxConcurrentFindMeFollowMeInvocation"],
							groupProfile["MaxConcurrentFindMeFollowMeInvocations"],
							groupProfile["UseMaxFindMeFollowMeDepth"],
							groupProfile["MaxFindMeFollowMeDepth"],
							groupProfile["MaxRedirectionDep"],
						)

					}
					return nil
				},
			},
			{
				Name:  "devices",
				Usage: "list device profile details per group",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "enterprise",
						Aliases: []string{"e"},
						Usage:   "enterprise ID",
					},
					&cli.StringFlag{
						Name:    "group",
						Aliases: []string{"g"},
						Usage:   "group ID",
					},
					&cli.StringFlag{
						Name:    "system",
						Aliases: []string{"s"},
						Usage:   "search for specific device type from system level",
					},
					&cli.BoolFlag{
						Name:  "header",
						Usage: "show column headers",
					},
					&cli.BoolFlag{
						Name:  "detail",
						Usage: "include line 1 user details",
					},
				},
				Action: func(c *cli.Context) error {

					// Generate a pseudo random sessionID
					SID := func() string {
						l := 20 // length
						buff := make([]byte, int(math.Round(float64(l)/float64(1.33333333333))))
						rand.Read(buff)
						str := base64.RawURLEncoding.EncodeToString(buff)
						return str[:l] // strip 1 extra character we get from odd length results
					}()

					if c.String("enterprise") != "" {
						if c.String("group") == "" {
							return fmt.Errorf("--group required")
						}
					}

					if c.String("group") != "" {
						if c.String("enterprise") == "" {
							return fmt.Errorf("--enterprise required")
						}
					}

					// Create an instance of client
					cl := &client{
						username:  config.Production.Username,
						password:  config.Production.Password,
						baseURL:   config.Production.URL,
						sessionID: SID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: SID,
						}
					}

					// Authenticate and login
					if err := cl.authenticationRequest(); err != nil {
						log.Fatal(err)
					}

					// Login
					if err := cl.loginRequest14sp4(); err != nil {
						log.Fatal(err)
					}

					// Group Level Query
					if c.String("system") == "" {
						// generate slice of devices
						devices := cl.GroupAccessDeviceGetListRequest(c.String("enterprise"), c.String("group"))

						if len(devices) == 0 {
							return fmt.Errorf("No devices found")
						}

						// print header if flagged
						if c.Bool("header") {
							if c.Bool("detail") {
								fmt.Printf("%v,%v,%v,%v,%v,%q,%v,%v,%v,%v,%v,%v\n",
									"deviceType",
									"deviceName",
									"macAddress",
									"useCustomUserNamePassword",
									"UserName",
									"version",
									"userId",
									"linePort",
									"lastName",
									"firstName",
									"phoneNumber",
									"extension",
								)
							} else {
								fmt.Printf("%v,%v,%v,%v,%v,%q\n",
									"deviceType",
									"deviceName",
									"macAddress",
									"useCustomUserNamePassword",
									"UserName",
									"version",
								)
							}

						}

						// loop thru each device and print details
						for i := 0; i < len(devices); i++ {

							deviceName := devices[i][0]
							deviceProfile := cl.GroupAccessDeviceGetRequest18sp1(c.String("enterprise"), c.String("group"), deviceName)
							deviceType := deviceProfile["deviceType"]
							macAddress := deviceProfile["macAddress"]
							UseCustomUserNamePassword := deviceProfile["useCustomUserNamePassword"]
							userName := deviceProfile["userName"]
							version := deviceProfile["version"]

							if c.Bool("detail") {

								// retrieve lines information
								lines := cl.GroupAccessDeviceGetUserListRequest21sp1(c.String("enterprise"), c.String("group"), deviceName)
								fmt.Printf("%v,%v,%v,%v,%v,%q,%v,%v,%v,%v,%v,%v\n",
									deviceType,
									deviceName,
									macAddress,
									UseCustomUserNamePassword,
									userName,
									version,
									lines["userID"],
									lines["linePort"],
									lines["lastName"],
									lines["firstName"],
									lines["phoneNumber"],
									lines["extension"],
								)

							} else {

								fmt.Printf("%v,%v,%v,%v,%v,%q\n",
									deviceType,
									deviceName,
									macAddress,
									UseCustomUserNamePassword,
									userName,
									version,
								)

							}
						}
						return nil
					}

					// System Level Query
					if c.String("system") != "" {
						devices := cl.SystemAccessDeviceGetAllRequest(c.String("system"))

						if len(devices) == 0 {
							return fmt.Errorf("No devices found")
						}

						if c.Bool("header") {
							fmt.Printf("%v,%v,%v,%v,%v,%q\n",
								"deviceType",
								"deviceName",
								"macAddress",
								"useCustomUserNamePassword",
								"UserName",
								"version",
							)
						}

						for i := 0; i < len(devices); i++ {
							fmt.Print(cl.GroupAccessDeviceGetRequest18sp1(devices[i][0], devices[i][2], devices[i][3]))
						}
					}
					return nil
				},
			},
			{
				Name:    "call-forward",
				Aliases: []string{"c"},
				Usage:   "list call forward always settings for each user in a group",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "enterprise",
						Aliases:  []string{"e"},
						Usage:    "enterprise ID",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "group",
						Aliases:  []string{"g"},
						Usage:    "group ID",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "header",
						Usage: "show output headers",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "active",
						Usage: "only show active call forwarding",
						Value: true,
					},
				},
				Action: func(c *cli.Context) error {
					SID := func() string {
						l := 20 // length
						buff := make([]byte, int(math.Round(float64(l)/float64(1.33333333333))))
						rand.Read(buff)
						str := base64.RawURLEncoding.EncodeToString(buff)
						return str[:l] // strip 1 extra character we get from odd length results
					}()

					// Create an instance of client
					cl := &client{
						username:  config.Production.Username,
						password:  config.Production.Password,
						baseURL:   config.Production.URL,
						sessionID: SID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: SID,
						}
					}

					// Authenticate and login
					err := cl.authenticationRequest()
					if err != nil {
						log.Fatal(err)
					}

					// Login
					err = cl.loginRequest14sp4()
					if err != nil {
						log.Fatal(err)
					}

					// Build a user list from the specified enterprise and group
					users := cl.UserGetListInGroupRequest(c.String("enterprise"), c.String("group"))

					if c.Bool("header") {
						fmt.Printf("%v,%v,%v,%v\n",
							"user",
							"serviceAssigned",
							"isActive",
							"forwardToPhoneNumber",
						)
					}

					if c.Bool("active") {
						for i := 0; i < len(users); i++ {

							CFASettings := cl.UserCallForwardingAlwaysGetRequest(users[i])

							// Create objx to convert some values to bool
							o := objx.New(CFASettings)

							serviceAssigned := o.Get("serviceAssigned").Bool()
							isActive := o.Get("isActive").Bool()
							forwardToPhoneNumber := CFASettings["forwardToPhoneNumber"]
							user := users[i]

							if isActive {
								fmt.Printf("%v,%v,%v,%v\n",
									user,
									serviceAssigned,
									isActive,
									forwardToPhoneNumber,
								)
							}
						}
						return nil
					}

					for i := 0; i < len(users); i++ {

						CFASettings := cl.UserCallForwardingAlwaysGetRequest(users[i])

						o := objx.New(CFASettings)

						serviceAssigned := o.Get("serviceAssigned").Bool()
						isActive := o.Get("isActive").Bool()
						forwardToPhoneNumber := CFASettings["forwardToPhoneNumber"]
						user := users[i]

						fmt.Printf("%v,%v,%v,%v\n",
							user,
							serviceAssigned,
							isActive,
							forwardToPhoneNumber,
						)
					}
					return nil
				},
			},
			{
				Name:  "sip-auth",
				Usage: "show the sip-authentication username for each user in the specified group",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "enterprise",
						Aliases:  []string{"e"},
						Usage:    "enteprise ID",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "group",
						Aliases:  []string{"g"},
						Usage:    "group ID",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "header",
						Usage: "show output headers",
						Value: false,
					},
				},
				Action: func(c *cli.Context) error {

					// Get a session ID
					SID := func() string {
						l := 20 // length
						buff := make([]byte, int(math.Round(float64(l)/float64(1.33333333333))))
						rand.Read(buff)
						str := base64.RawURLEncoding.EncodeToString(buff)
						return str[:l] // strip 1 extra character we get from odd length results
					}()

					// Create an instance of client
					cl := &client{
						username:  config.Production.Username,
						password:  config.Production.Password,
						baseURL:   config.Production.URL,
						sessionID: SID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: SID,
						}
					}

					// Authenticate
					if err := cl.authenticationRequest(); err != nil {
						log.Fatal(err)
					}

					// Login
					if err := cl.loginRequest14sp4(); err != nil {
						log.Fatal(err)
					}

					if c.Bool("header") {
						fmt.Printf("%v,%v\n",
							"userID",
							"authID",
						)
					}
					users := cl.UserGetListInGroupRequest(c.String("enterprise"), c.String("group"))
					for i := 0; i < len(users); i++ {
						authID := cl.UserAuthenticationGetRequest(users[i])
						fmt.Printf("%v,%v\n", users[i], authID)
					}
					return nil

				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(fmt.Printf("\n%v\n", err))
	}

}
