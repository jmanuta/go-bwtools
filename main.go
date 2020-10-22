package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/net/html/charset"
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

// SOAPEnvelope for unmarshalling responses
type SOAPEnvelope struct {
	XMLName  xml.Name `xml:"Envelope"`
	SOAPBody struct {
		XMLName                   xml.Name `xml:"Body"`
		ProcessOCIMessageResponse struct {
			XMLName                 xml.Name `xml:"processOCIMessageResponse"`
			ProcessOCIMessageReturn string   `xml:"processOCIMessageReturn"`
		}
		Fault struct {
			XMLName    xml.Name `xml:"Fault"`
			FaultCode  string   `xml:"faultcode"`
			FaultActor string   `xml:"faultactor"`
			Detail     struct {
				XMLName  xml.Name `xml:"detail"`
				Hostname string   `xml:"hostname"`
				String   string   `xml:"string"`
			}
		}
	}
}

// ColHeading for tables
type ColHeading struct {
	XMLName xml.Name `xml:"colHeading"`
	Content string   `xml:",chardata"`
}

// Col for rows
type Col struct {
	XMLName xml.Name `xml:"col"`
	Content string   `xml:",chardata"`
}

// Row for tables
type Row struct {
	XMLName xml.Name `xml:"row"`
	Col     []Col    `xml:"col"`
}

// BroadsoftDocument OCI fields
type BroadsoftDocument struct {
	XMLName   xml.Name `xml:"BroadsoftDocument"`
	SessionID string   `xml:"sessionId"`
	Command   struct {
		XMLName                                             xml.Name `xml:"command"`
		AllowAlternateNumbersForRedirectingIdentity         bool     `xml:"allowAlternateNumbersForRedirectingIdentity"`
		AllowConfigurableCLIDForRedirectingIdentity         bool     `xml:"allowConfigurableCLIDForRedirectingIdentity"`
		AllowDepartmentCLIDNameOverride                     bool     `xml:"allowDepartmentCLIDNameOverride"`
		AllowEnterpriseGroupCallTypingForPrivateDialingPlan bool     `xml:"allowEnterpriseGroupCallTypingForPrivateDialingPlan"`
		AllowEnterpriseGroupCallTypingForPublicDialingPlan  bool     `xml:"allowEnterpriseGroupCallTypingForPublicDialingPlan"`
		BlockCallingNameForExternalCalls                    bool     `xml:"blockCallingNameForExternalCalls"`
		ClidPolicy                                          string   `xml:"clidPolicy"`
		ConfigurationMode                                   string   `xml:"configurationMode"`
		Description                                         string   `xml:"description"`
		DeviceType                                          string   `xml:"deviceType"`
		EmergencyClidPolicy                                 string   `xml:"emergencyClidPolicy"`
		EnableDialableCallerID                              bool     `xml:"enableDialableCallerID"`
		EnableEnterpriseExtensionDialing                    bool     `xml:"enableEnterpriseExtensionDialing"`
		EnablePhoneListLookup                               bool     `xml:"enablePhoneListLookup"`
		EnforceEnterpriseCallingLineIdentityRestriction     bool     `xml:"enforceEnterpriseCallingLineIdentityRestriction"`
		EnforceGroupCallingLineIdentityRestriction          bool     `xml:"enforceGroupCallingLineIdentityRestriction"`
		EnterpriseCallsCLIDPolicy                           string   `xml:"enterpriseCallsCLIDPolicy"`
		ForwardToPhoneNumber                                string   `xml:"forwardToPhoneNumber"`
		GroupCallsCLIDPolicy                                string   `xml:"groupCallsCLIDPolicy"`
		IsActive                                            bool     `xml:"isActive"`
		IsRingSplashActive                                  string   `xml:"isRingSplashActive"`
		MacAddress                                          string   `xml:"macAddress"`
		MaxCallTimeForAnsweredCallsMinutes                  int      `xml:"maxCallTimeForAnsweredCallsMinutes"`
		MaxCallTimeForUnansweredCallsMinutes                int      `xml:"maxCallTimeForUnansweredCallsMinutes"`
		MaxConcurrentFindMeFollowMeInvocations              int      `xml:"maxConcurrentFindMeFollowMeInvocations"`
		MaxConcurrentRedirectedCalls                        int      `xml:"maxConcurrentRedirectedCalls"`
		MaxFindMeFollowMeDepth                              int      `xml:"maxFindMeFollowMeDepth"`
		MaxRedirectionDepth                                 int      `xml:"maxRedirectionDepth"`
		MaxSimultaneousCalls                                int      `xml:"maxSimultaneousCalls"`
		MaxSimultaneousVideoCalls                           int      `xml:"maxSimultaneousVideoCalls"`
		MediaPolicySelection                                string   `xml:"mediaPolicySelection"`
		NetAddress                                          string   `xml:"netAddress"`
		NetworkUsageSelection                               string   `xml:"NetworkUsageSelection"`
		Nonce                                               string   `xml:"nonce"`
		NumberOfAssignedPorts                               int      `xml:"numberOfAssignedPorts"`
		OutboundProxyServerNetAddress                       string   `xml:"outboundProxyServerNetAddress"`
		OverrideCLIDRestrictionForPrivateCallCategory       bool     `xml:"overrideCLIDRestrictionForPrivateCallCategory"`
		PassAlgo                                            string   `xml:"passwordAlgorithm"`
		PhysicalLocation                                    string   `xml:"physicalLocation"`
		Port                                                string   `xml:"port"`
		Protocol                                            string   `xml:"protocol"`
		RType                                               string   `xml:"type,attr"`
		SerialNumber                                        string   `xml:"serialNumber"`
		Status                                              string   `xml:"status"`
		StunServerNetAddress                                string   `xml:"stunServerNetAddress"`
		Summary                                             string   `xml:"summary"`
		SummaryEnglish                                      string   `xml:"summaryEnglish"`
		TransportProtocol                                   string   `xml:"transportProtocol"`
		UseCustomUserNamePassword                           bool     `xml:"useCustomUserNamePassword"`
		UseEnterpriseCLIDForPrivateCallCategory             bool     `xml:"useEnterpriseCLIDForPrivateCallCategory"`
		UseGroupCallLimitsSetting                           bool     `xml:"useGroupCallLimitsSetting"`
		UseGroupDCLIDSetting                                bool     `xml:"useGroupDCLIDSetting"`
		UseGroupName                                        bool     `xml:"useGroupName"`
		UseMaxCallTimeForAnsweredCalls                      bool     `xml:"useMaxCallTimeForAnsweredCalls"`
		UseMaxCallTimeForUnansweredCalls                    bool     `xml:"useMaxCallTimeForUnansweredCalls"`
		UseMaxConcurrentFindMeFollowMeInvocations           bool     `xml:"useMaxConcurrentFindMeFollowMeInvocations"`
		UseMaxConcurrentRedirectedCalls                     bool     `xml:"useMaxConcurrentRedirectedCalls"`
		UseMaxFindMeFollowMeDepth                           bool     `xml:"useMaxFindMeFollowMeDepth"`
		UseMaxSimultaneousCalls                             bool     `xml:"useMaxSimultaneousCalls"`
		UseMaxSimultaneousVideoCalls                        bool     `xml:"useMaxSimultaneousVideoCalls"`
		UseServiceProviderDCLIDSetting                      bool     `xml:"useServiceProviderDCLIDSetting"`
		UseSettingLevel                                     string   `xml:"useSettingLevel"`
		UseUserCLIDSetting                                  bool     `xml:"useUserCLIDSetting"`
		UseUserCallLimitsSetting                            bool     `xml:"useUserCallLimitsSetting"`
		UseUserDCLIDSetting                                 bool     `xml:"useUserDCLIDSetting"`
		UseUserMediaSetting                                 bool     `xml:"useUserMediaSetting"`
		UseUserPhoneListLookupSetting                       bool     `xml:"useUserPhoneListLookupSetting"`
		UserID                                              string   `xml:"userId"`
		UserName                                            string   `xml:"userName"`
		Version                                             string   `xml:"version"`
		UserTable                                           struct {
			XMLName    xml.Name     `xml:"userTable"`
			ColHeading []ColHeading `xml:"colHeading,omitempty"`
			Row        []Row        `xml:"row,omitempty"`
		}
		AccessDeviceTable struct {
			XMLName    xml.Name     `xml:"accessDeviceTable"`
			ColHeading []ColHeading `xml:"colHeading,omitempty"`
			Row        []Row        `xml:"row,omitempty"`
		}
		NumberOfPorts struct {
			XMLName  xml.Name `xml:"numberOfPorts"`
			Quantity int      `xml:"quantity"`
		}
		DeviceUserTable struct {
			XMLName    xml.Name     `xml:"deviceUserTable"`
			ColHeading []ColHeading `xml:"colHeading,omitempty"`
			Row        []Row        `xml:"row,omitempty"`
		}
	}
}

// AuthenticationRequest Send authentication
func (c *client) authenticationRequest() error {

	// Create command
	data := `<command xmlns="" xsi:type="AuthenticationRequest">`
	data += fmt.Sprintf(`<userId>%s</userId>`, c.username)
	data += `</command>`

	// Send command
	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("SOAPEnvelope unmarshalling error")
		//panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	// create the instance
	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Parsed xml
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	// Check for errors
	if parsed.Command.RType == "c:ErrorResponse" {
		return fmt.Errorf("%v", parsed.Command.SummaryEnglish)
	}

	// Store the nonce on the client
	c.nonce = parsed.Command.Nonce
	return nil
}

// LoginRequest14sp4 Send login
func (c *client) loginRequest14sp4() error {

	// Generate the hash
	digestSha := sha1.Sum([]byte(c.password))
	digestShaString := hex.EncodeToString(digestSha[:])
	digestMd5 := md5.Sum([]byte(fmt.Sprintf(`%s:%s`, c.nonce, digestShaString)))
	digestMd5String := hex.EncodeToString(digestMd5[:])
	c.hash = digestMd5String

	// Create the message
	data := `<command xmlns="" xsi:type="LoginRequest14sp4">`
	data += fmt.Sprintf(`<userId>%s</userId>`, c.username)
	data += fmt.Sprintf(`<signedPassword>%s</signedPassword>`, c.hash)
	data += `</command>`

	// Send the message
	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	// Create instance to store data
	var parsed BroadsoftDocument

	// Create reader for data in message return
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	// Check for errors
	if parsed.Command.RType == "c:ErrorResponse" {
		return fmt.Errorf("%v", parsed.Command.SummaryEnglish)
	}

	return nil
}

// ServiceProviderCallProcessingGetPolicyRequest21Sp1 Get Enterprise1
func (c client) serviceProviderCallProcessingGetPolicyRequest21Sp1(enterprise string) string {

	data := `<command xmlns="" xsi:type="ServiceProviderCallProcessingGetPolicyRequest21sp1">`
	data += fmt.Sprintf(`<serviceProviderId>%s</serviceProviderId>`, enterprise)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	var parsed BroadsoftDocument

	// Create a reader for the OCI message
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%v,n/a,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n", enterprise, parsed.Command.UseMaxSimultaneousCalls,
		parsed.Command.MaxSimultaneousCalls, parsed.Command.UseMaxSimultaneousVideoCalls, parsed.Command.MaxSimultaneousVideoCalls, parsed.Command.UseMaxCallTimeForAnsweredCalls,
		parsed.Command.MaxCallTimeForAnsweredCallsMinutes, parsed.Command.UseMaxCallTimeForUnansweredCalls, parsed.Command.MaxCallTimeForUnansweredCallsMinutes,
		parsed.Command.UseMaxConcurrentRedirectedCalls, parsed.Command.MaxConcurrentRedirectedCalls, parsed.Command.UseMaxConcurrentFindMeFollowMeInvocations,
		parsed.Command.MaxConcurrentFindMeFollowMeInvocations, parsed.Command.UseMaxFindMeFollowMeDepth, parsed.Command.MaxFindMeFollowMeDepth, parsed.Command.MaxRedirectionDepth)
}

// ServiceProviderCallProcessingModifyPolicyRequest15 Set Enterprise
func (c client) serviceProviderCallProcessingModifyPolicyRequest15() {
}

// GroupCallProcessingGetPolicyRequest21Sp1 Get Group
func (c client) groupCallProcessingGetPolicyRequest21Sp1(enterprise, group string) string {

	data := `<command xmlns="" xsi:type="GroupCallProcessingGetPolicyRequest21sp1">`
	data += fmt.Sprintf(`<serviceProviderId>%s</serviceProviderId>`, enterprise)
	data += fmt.Sprintf(`<groupId>%s</groupId>`, group)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%v-%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n", enterprise, group, parsed.Command.UseGroupCallLimitsSetting, parsed.Command.UseMaxSimultaneousCalls,
		parsed.Command.MaxSimultaneousCalls, parsed.Command.UseMaxSimultaneousVideoCalls, parsed.Command.MaxSimultaneousVideoCalls, parsed.Command.UseMaxCallTimeForAnsweredCalls,
		parsed.Command.MaxCallTimeForAnsweredCallsMinutes, parsed.Command.UseMaxCallTimeForUnansweredCalls, parsed.Command.MaxCallTimeForUnansweredCallsMinutes,
		parsed.Command.UseMaxConcurrentRedirectedCalls, parsed.Command.MaxConcurrentRedirectedCalls, parsed.Command.UseMaxConcurrentFindMeFollowMeInvocations,
		parsed.Command.MaxConcurrentFindMeFollowMeInvocations, parsed.Command.UseMaxFindMeFollowMeDepth, parsed.Command.MaxFindMeFollowMeDepth, parsed.Command.MaxRedirectionDepth)

}

// GroupCallProcessingModifyPolicyRequest15Sp2 Set Group
func (c client) groupCallProcessingModifyPolicyRequest15Sp2() {
}

// UserCallProcessingGetPolicyRequest21Sp1 Get User
func (c client) userCallProcessingGetPolicyRequest21Sp1(user string) string {

	data := `<command xmlns="" xsi:type="UserCallProcessingGetPolicyRequest21sp1">`
	data += fmt.Sprintf(`<userId>%s</userId>`, user)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	// Create instance to store data
	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n", user, parsed.Command.UseUserCallLimitsSetting, parsed.Command.UseMaxSimultaneousCalls,
		parsed.Command.MaxSimultaneousCalls, parsed.Command.UseMaxSimultaneousVideoCalls, parsed.Command.MaxSimultaneousVideoCalls, parsed.Command.UseMaxCallTimeForAnsweredCalls,
		parsed.Command.MaxCallTimeForAnsweredCallsMinutes, parsed.Command.UseMaxCallTimeForUnansweredCalls, parsed.Command.MaxCallTimeForUnansweredCallsMinutes,
		parsed.Command.UseMaxConcurrentRedirectedCalls, parsed.Command.MaxConcurrentRedirectedCalls, parsed.Command.UseMaxConcurrentFindMeFollowMeInvocations,
		parsed.Command.MaxConcurrentFindMeFollowMeInvocations, parsed.Command.UseMaxFindMeFollowMeDepth, parsed.Command.MaxFindMeFollowMeDepth, parsed.Command.MaxRedirectionDepth)
}

// Group user list
func (c client) UserGetListInGroupRequest(enterprise string, group string) []string {

	data := `<command xmlns="" xsi:type="UserGetListInGroupRequest">`
	data += fmt.Sprintf(`<serviceProviderId>%s</serviceProviderId>`, enterprise)
	data += fmt.Sprintf(`<GroupId>%s</GroupId>`, group)
	data += fmt.Sprintf(`<responseSizeLimit>%s</responseSizeLimit>`, "2000")
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	// Create instance to store data
	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	var users []string

	// Iterate over the rows to print the userID
	for i := 0; i < len(parsed.Command.UserTable.Row); i++ {
		users = append(users, parsed.Command.UserTable.Row[i].Col[0].Content)
	}

	return users

}

// UserCallProcessingModifyPolicyRequest14Sp7 Set User
func (c client) userCallProcessingModifyPolicyRequest14Sp7(user string, UseUserCallLimitsSetting bool, UseMaxSimultaneousCalls bool, MaxSimultaneousCalls int,
	UseMaxSimultaneousVideoCalls bool, MaxSimultaneousVideoCalls int, UseMaxCallTimeForAnsweredCall bool, MaxCallTimeForAnsweredCallsMinutes int,
	UseMaxCallTimeForUnansweredCalls bool, MaxCallTimeForUnansweredCallsMinutes int, UseMaxConcurrentRedirectedCalls bool, MaxConcurrentRedirectedCalls int,
	UseMaxConcurrentFindMeFollowMeInvocations bool, MaxConcurrentFindMeFollowMeInvocations int, UseMaxFindMeFollowMeDepth bool, MaxFindMeFollowMeDepth int,
	MaxRedirectionDepth int) {

	data := `<command xmlns="" xsi:type="UserCallProcessingModifyPolicyRequest14sp7">`
	data += fmt.Sprintf(`<userId>%v</userId>`, user)
	data += fmt.Sprintf(`<useUserCallLimitsSetting>%v</useUserCallLimitsSetting>`, UseUserCallLimitsSetting)
	data += fmt.Sprintf(`<useMaxSimultaneousCalls>%v</useMaxSimultaneousCalls>`, UseMaxSimultaneousCalls)
	data += fmt.Sprintf(`<maxSimultaneousCalls>%v</maxSimultaneousCalls>`, MaxSimultaneousCalls)
	data += fmt.Sprintf(`<useMaxSimultaneousVideoCalls>%v</useMaxSimultaneousVideoCalls>`, UseMaxSimultaneousVideoCalls)
	data += fmt.Sprintf(`<maxSimultaneousVideoCalls>%v</maxSimultaneousVideoCalls>`, MaxSimultaneousVideoCalls)
	data += fmt.Sprintf(`<useMaxCallTimeForAnsweredCalls>%v</useMaxCallTimeForAnsweredCalls>`, UseMaxCallTimeForAnsweredCall)
	data += fmt.Sprintf(`<maxCallTimeForAnsweredCallsMinutes>%v</maxCallTimeForAnsweredCallsMinutes>`, MaxCallTimeForAnsweredCallsMinutes)
	data += fmt.Sprintf(`<useMaxCallTimeForUnansweredCalls>%v</useMaxCallTimeForUnansweredCalls>`, UseMaxCallTimeForUnansweredCalls)
	data += fmt.Sprintf(`<maxCallTimeForUnansweredCallsMinutes>%v</maxCallTimeForUnansweredCallsMinutes>`, MaxCallTimeForUnansweredCallsMinutes)
	data += fmt.Sprintf(`<useMaxConcurrentRedirectedCalls>%v</useMaxConcurrentRedirectedCalls>`, UseMaxConcurrentRedirectedCalls)
	data += fmt.Sprintf(`<maxConcurrentRedirectedCalls>%v</maxConcurrentRedirectedCalls>`, MaxConcurrentRedirectedCalls)
	data += fmt.Sprintf(`<useMaxFindMeFollowMeDepth>%v</useMaxFindMeFollowMeDepth>`, UseMaxFindMeFollowMeDepth)
	data += fmt.Sprintf(`<maxFindMeFollowMeDepth>%v</maxFindMeFollowMeDepth>`, MaxFindMeFollowMeDepth)
	data += fmt.Sprintf(`<maxRedirectionDepth>%v</maxRedirectionDepth>`, MaxRedirectionDepth)
	data += fmt.Sprintf(`<useMaxConcurrentFindMeFollowMeInvocations>%v</useMaxConcurrentFindMeFollowMeInvocations>`, UseMaxConcurrentFindMeFollowMeInvocations)
	data += fmt.Sprintf(`<maxConcurrentFindMeFollowMeInvocations>%v</maxConcurrentFindMeFollowMeInvocations>`, MaxConcurrentFindMeFollowMeInvocations)
	//data += `<useUserCLIDSetting>true</useUserCLIDSetting>`
	//data += `<useUserMediaSetting>false</useUserMediaSetting>`
	//data += `<useUserDCLIDSetting>false</useUserDCLIDSetting>`
	//data += `<mediaPolicySelection>No Restrictions</mediaPolicySelection>`
	//data += `<supportedMediaSetName xsi:nil="true"/>`
	//data += `<clidPolicy>Use Configurable CLID</clidPolicy>`
	//data += `<emergencyClidPolicy>Use Configurable CLID</emergencyClidPolicy>`
	//data += `<allowAlternateNumbersForRedirectingIdentity>true</allowAlternateNumbersForRedirectingIdentity>`
	//data += `<useGroupName>false</useGroupName>`
	//data += `<enableDialableCallerID>false</enableDialableCallerID>`
	//data += `<blockCallingNameForExternalCalls>false</blockCallingNameForExternalCalls>`
	//data += `<allowConfigurableCLIDForRedirectingIdentity>true</allowConfigurableCLIDForRedirectingIdentity>`
	//data += `<allowDepartmentCLIDNameOverride>false</allowDepartmentCLIDNameOverride>`
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s\n", err))
	}

	// Create instance to store data
	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", parsed)

}

// Get a list off all devices in a group
func (c client) GroupAccessDeviceGetListRequest(enterprise string, group string) [][]string {

	responseLimit := 1000

	data := `<command xsi:type="GroupAccessDeviceGetListRequest" xmlns="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
	data += fmt.Sprintf(`<serviceProviderId>%s</serviceProviderId>`, enterprise)
	data += fmt.Sprintf(`<groupId>%s</groupId>`, group)
	data += fmt.Sprintf(`<responseSizeLimit>%v</responseSizeLimit>`, responseLimit)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	// Create instance to store data
	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	// Object to hold all devices
	var devices [][]string

	// Loop over each row of devices
	for i := 0; i < len(parsed.Command.AccessDeviceTable.Row); i++ {

		// Object to hold a single device's settings
		var device []string

		// Loop over each setting on the device
		for j := 0; j < len(parsed.Command.AccessDeviceTable.Row[i].Col); j++ {

			// Append each setting to the device var
			device = append(device, parsed.Command.AccessDeviceTable.Row[i].Col[j].Content)
		}

		// Append the device to the devices var
		devices = append(devices, device)
	}

	return devices
}

// Get a specific device profile
func (c client) GroupAccessDeviceGetRequest18sp1(enterprise string, group string, device string) (string, string, bool, string, string) {

	data := `<command xsi:type="GroupAccessDeviceGetRequest18sp1" xmlns="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
	data += fmt.Sprintf(`<serviceProviderId>%s</serviceProviderId>`, enterprise)
	data += fmt.Sprintf(`<groupId>%s</groupId>`, group)
	data += fmt.Sprintf(`<deviceName>%s</deviceName>`, device)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	//return fmt.Sprintf("%v,%v,%v,%v,%v,%v,", parsed.Command.DeviceType, device, parsed.Command.MacAddress, parsed.Command.UseCustomUserNamePassword, parsed.Command.UserName, parsed.Command.Version)
	return parsed.Command.DeviceType, parsed.Command.MacAddress, parsed.Command.UseCustomUserNamePassword, parsed.Command.UserName, parsed.Command.Version

}

func (c client) GroupAccessDeviceGetUserListRequest21sp1(enterprise, group, device string) map[string]interface{} {

	// Limit number of results
	limit := 50

	data := `<command echo="#HidePrimaryLinePortForTrunkUser#" xsi:type="GroupAccessDeviceGetUserListRequest21sp1" xmlns="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
	data += fmt.Sprintf(`<serviceProviderId>%v</serviceProviderId>`, enterprise)
	data += fmt.Sprintf(`<groupId>%v</groupId>`, group)
	data += fmt.Sprintf(`<deviceName>%v</deviceName>`, device)
	data += fmt.Sprintf(`<responseSizeLimit>%v</responseSizeLimit>`, limit)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	// Interface is used since values are mixed type
	lines := make(map[string]interface{})

	// loop through rows to collect all users assigned to the device
	for i := 0; i < len(parsed.Command.DeviceUserTable.Row); i++ {
		lines["linePort"] = parsed.Command.DeviceUserTable.Row[i].Col[0].Content
		lines["lastName"] = parsed.Command.DeviceUserTable.Row[i].Col[1].Content
		lines["firstName"] = parsed.Command.DeviceUserTable.Row[i].Col[2].Content
		lines["phoneNumber"] = parsed.Command.DeviceUserTable.Row[i].Col[3].Content
		lines["userID"] = parsed.Command.DeviceUserTable.Row[i].Col[4].Content
		lines["userType"] = parsed.Command.DeviceUserTable.Row[i].Col[5].Content
		lines["endpointType"] = parsed.Command.DeviceUserTable.Row[i].Col[6].Content
		lines["order"] = parsed.Command.DeviceUserTable.Row[i].Col[7].Content
		lines["isPrimaryLine"] = parsed.Command.DeviceUserTable.Row[i].Col[8].Content
		lines["extension"] = parsed.Command.DeviceUserTable.Row[i].Col[9].Content
		lines["department"] = parsed.Command.DeviceUserTable.Row[i].Col[10].Content
		lines["emailAddress"] = parsed.Command.DeviceUserTable.Row[i].Col[11].Content
		lines["privateIdentity"] = parsed.Command.DeviceUserTable.Row[i].Col[12].Content
	}

	return lines
}

func (c client) SystemAccessDeviceGetAllRequest(deviceType string) [][]string {

	// Set limit of results
	limit := 5000

	data := `<command xsi:type="SystemAccessDeviceGetAllRequest" xmlns="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`
	data += fmt.Sprintf(`<responseSizeLimit>%v</responseSizeLimit>`, limit)
	data += `<searchCriteriaExactDeviceType>`
	data += fmt.Sprintf(`<deviceType>%s</deviceType>`, deviceType)
	data += `</searchCriteriaExactDeviceType>`
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	// Create the object to store the OCI response
	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	// Object to hold all devices
	var devices [][]string

	// Loop over each row of devices
	for i := 0; i < len(parsed.Command.AccessDeviceTable.Row); i++ {

		// Object to hold a single device's settings
		var device []string

		// Loop over each setting on the device
		for j := 0; j < len(parsed.Command.AccessDeviceTable.Row[i].Col); j++ {

			// Append each setting to the device var
			device = append(device, parsed.Command.AccessDeviceTable.Row[i].Col[j].Content)
		}

		// Append the device to the devices var
		devices = append(devices, device)
	}

	return devices
}

func (c client) UserCallForwardingAlwaysGetRequest(user string) (string, bool, bool, string) {

	data := `<command xmlns="" xsi:type="UserCallForwardingAlwaysGetRequest">`
	data += fmt.Sprintf(`<userId>%v</userId>`, user)
	data += `</command>`

	body, _ := c.sendRequest(html.EscapeString(data))

	var resp SOAPEnvelope
	if err := xml.Unmarshal(body, &resp); err != nil {
		panic(fmt.Sprintf("Issue unmarshalling SOAPEnvelope: %s", err))
	}

	// Create instance to store data
	var parsed BroadsoftDocument

	// Create a reader containing []byte of xml. This xml is escaped i.e. &lt instead of <
	reader := bytes.NewReader([]byte(resp.SOAPBody.ProcessOCIMessageResponse.ProcessOCIMessageReturn))

	// Use the NewDecoder on the reader and store
	decoder := xml.NewDecoder(reader)

	// Set the Charset on the decoder
	decoder.CharsetReader = charset.NewReaderLabel

	// Write the decorder to the parsed instance
	if err := decoder.Decode(&parsed); err != nil {
		panic(err)
	}

	// user, serviceAssigned, isActive, ForwardToPhoneNumber
	if parsed.Command.RType == "c:ErrorResponse" {
		if strings.Contains(parsed.Command.SummaryEnglish, "[Error 4410]") {
			return user, false, false, ""
		}
		return user, false, false, ""
	}

	return user, true, parsed.Command.IsActive, parsed.Command.ForwardToPhoneNumber
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

func (c *client) makeConfig(path string) {

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

	config := &Config{}
	file, err := os.Open("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		log.Fatal(err)
	}

}

func main() {

	// Removes timestamp from error output
	log.SetFlags(0)
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

	config := &Config{}
	file, err := os.Open("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		log.Fatal(err)
	}

	app := &cli.App{
		Name:    "BWTools",
		Version: "v1.1.0",
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
			&cli.BoolFlag{
				Name:  "header",
				Usage: "show column headers",
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
					sID := func() string {
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
						sessionID: sID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: sID,
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
						fmt.Println("userId,useUserCallLimitsSetting,useMaxSimultaneousCalls,maxSimultaneousCalls,useMaxSimultaneousVideoCalls," +
							"maxSimultaneousVideoCalls,useMaxCallTimeForAnsweredCalls,maxCallTimeForAnsweredCallsMinutes,useMaxCallTimeForUnansweredCalls," +
							"maxCallTimeForUnansweredCallsMinutes,useMaxConcurrentRedirectedCalls,maxConcurrentRedirectedCalls,useMaxFindMeFollowMeDepth," +
							"maxFindMeFollowMeDepth,maxRedirectionDepth,useMaxConcurrentFindMeFollowMeInvocations,maxConcurrentFindMeFollowMeInvocations",
						)
					}

					// Iterate through user list and retrieve the CP Policy for each
					for i := 0; i < len(users); i++ {
						fmt.Print(cl.userCallProcessingGetPolicyRequest21Sp1(users[i]))
					}

					if c.Bool("include") {
						if c.Bool("header") {
							fmt.Println("enterprise,n/a,useMaxSimultaneousCalls,maxSimultaneousCalls,useMaxSimultaneousVideoCalls," +
								"maxSimultaneousVideoCalls,useMaxCallTimeForAnsweredCalls,maxCallTimeForAnsweredCallsMinutes,useMaxCallTimeForUnansweredCalls," +
								"maxCallTimeForUnansweredCallsMinutes,useMaxConcurrentRedirectedCalls,maxConcurrentRedirectedCalls,useMaxFindMeFollowMeDepth," +
								"maxFindMeFollowMeDepth,maxRedirectionDepth,useMaxConcurrentFindMeFollowMeInvocations,maxConcurrentFindMeFollowMeInvocations",
							)
						}
						fmt.Print(cl.serviceProviderCallProcessingGetPolicyRequest21Sp1(c.String("enterprise")))
						if c.Bool("header") {
							fmt.Println("enterprise-group,useUserGroupLimitsSetting, useMaxSimultaneousCalls,maxSimultaneousCalls,useMaxSimultaneousVideoCalls," +
								"maxSimultaneousVideoCalls,useMaxCallTimeForAnsweredCalls,maxCallTimeForAnsweredCallsMinutes,useMaxCallTimeForUnansweredCalls," +
								"maxCallTimeForUnansweredCallsMinutes,useMaxConcurrentRedirectedCalls,maxConcurrentRedirectedCalls,useMaxFindMeFollowMeDepth," +
								"maxFindMeFollowMeDepth,maxRedirectionDepth,useMaxConcurrentFindMeFollowMeInvocations,maxConcurrentFindMeFollowMeInvocations",
							)
						}
						fmt.Print(cl.groupCallProcessingGetPolicyRequest21Sp1(c.String("enterprise"), c.String("group")))
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
					sID := func() string {
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
						sessionID: sID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: sID,
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
							fmt.Println("deviceType,deviceName,macAddress,useCustomUserNamePassword,UserName,version,userId,linePort,lastName,firstName,phoneNumber,extension")
						}

						// loop thru each device and print details
						for i := 0; i < len(devices); i++ {

							deviceName := devices[i][0]
							deviceType, macAddress, UseCustomUserNamePassword, userName, version := cl.GroupAccessDeviceGetRequest18sp1(c.String("enterprise"), c.String("group"), deviceName)

							if c.Bool("detail") {

								// retrieve lines information
								lines := cl.GroupAccessDeviceGetUserListRequest21sp1(c.String("enterprise"), c.String("group"), deviceName)
								fmt.Printf("%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n", deviceType, deviceName, macAddress, UseCustomUserNamePassword, userName, version, lines["userID"], lines["linePort"], lines["lastName"], lines["firstName"], lines["phoneNumber"], lines["extension"])

							} else {

								fmt.Printf("%v,%v,%v,%v,%v,%v\n", deviceType, deviceName, macAddress, UseCustomUserNamePassword, userName, version)

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
							fmt.Println("deviceType,deviceName,macAddress,useCustomUserNamePassword,UserName,version")
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
					sID := func() string {
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
						sessionID: sID,
					}

					// Check if lab flag is set
					if c.Bool("lab") {
						cl = &client{
							username:  config.Lab.Username,
							password:  config.Lab.Password,
							baseURL:   config.Lab.URL,
							sessionID: sID,
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
						fmt.Println("user,serviceAssigned,isActive,forwardToPhoneNumber")
					}

					if c.Bool("active") {
						for i := 0; i < len(users); i++ {
							user, serviceAssigned, isActive, forwardToPhoneNumber := cl.UserCallForwardingAlwaysGetRequest(users[i])
							if isActive {
								fmt.Printf("%v,%v,%v,%v\n", user, serviceAssigned, isActive, forwardToPhoneNumber)
							}
						}
						return nil
					}

					for i := 0; i < len(users); i++ {
						user, serviceAssigned, isActive, forwardToPhoneNumber := cl.UserCallForwardingAlwaysGetRequest(users[i])
						fmt.Printf("%v,%v,%v,%v\n", user, serviceAssigned, isActive, forwardToPhoneNumber)
					}
					return nil
				},
			},
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(fmt.Printf("\n%v\n", err))
	}

}
