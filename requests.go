package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html"
	"strings"

	"golang.org/x/net/html/charset"
)

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
func (c client) serviceProviderCallProcessingGetPolicyRequest21Sp1(enterprise string) map[string]interface{} {

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

	profile := make(map[string]interface{})

	profile["UseMaxSimultaneousCalls"] = parsed.Command.UseMaxSimultaneousCalls
	profile["MaxSimultaneousCalls"] = parsed.Command.MaxSimultaneousCalls
	profile["UseMaxSimultaneousVideoCalls"] = parsed.Command.UseMaxSimultaneousVideoCalls
	profile["MaxSimultaneousVideoCalls"] = parsed.Command.MaxSimultaneousVideoCalls
	profile["UseMaxCallTimeForAnsweredCalls"] = parsed.Command.UseMaxCallTimeForAnsweredCalls
	profile["MaxCallTimeForAnsweredCallsMinutes"] = parsed.Command.MaxCallTimeForAnsweredCallsMinutes
	profile["UseMaxCallTimeForUnansweredCall"] = parsed.Command.UseMaxCallTimeForUnansweredCalls
	profile["MaxCallTimeForUnansweredCallsMinutes"] = parsed.Command.MaxCallTimeForUnansweredCallsMinutes
	profile["UseMaxConcurrentRedirectedCalls"] = parsed.Command.UseMaxConcurrentRedirectedCalls
	profile["MaxConcurrentRedirectedCalls"] = parsed.Command.MaxConcurrentRedirectedCalls
	profile["UseMaxConcurrentFindMeFollowMeInvocations"] = parsed.Command.UseMaxConcurrentFindMeFollowMeInvocations
	profile["MaxConcurrentFindMeFollowMeInvocations"] = parsed.Command.MaxConcurrentFindMeFollowMeInvocations
	profile["UseMaxFindMeFollowMeDepth"] = parsed.Command.UseMaxFindMeFollowMeDepth
	profile["MaxFindMeFollowMeDepth"] = parsed.Command.MaxFindMeFollowMeDepth
	profile["MaxRedirectionDepth"] = parsed.Command.MaxRedirectionDepth

	return profile
}

// ServiceProviderCallProcessingModifyPolicyRequest15 Set Enterprise
func (c client) serviceProviderCallProcessingModifyPolicyRequest15() {
}

// GroupCallProcessingGetPolicyRequest21Sp1 Get Group
func (c client) groupCallProcessingGetPolicyRequest21Sp1(enterprise, group string) map[string]interface{} {

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

	profile := make(map[string]interface{})

	profile["UseGroupCallLimitsSetting"] = parsed.Command.UseGroupCallLimitsSetting
	profile["UseMaxSimultaneousCall"] = parsed.Command.UseMaxSimultaneousCalls
	profile["MaxSimultaneousCalls"] = parsed.Command.MaxSimultaneousCalls
	profile["UseMaxSimultaneousVideoCalls"] = parsed.Command.UseMaxSimultaneousVideoCalls
	profile["MaxSimultaneousVideoCalls"] = parsed.Command.MaxSimultaneousVideoCalls
	profile["UseMaxCallTimeForAnsweredCall"] = parsed.Command.UseMaxCallTimeForAnsweredCalls
	profile["MaxCallTimeForAnsweredCallsMinutes"] = parsed.Command.MaxCallTimeForAnsweredCallsMinutes
	profile["UseMaxCallTimeForUnansweredCalls"] = parsed.Command.UseMaxCallTimeForUnansweredCalls
	profile["MaxCallTimeForUnansweredCallsMinute"] = parsed.Command.MaxCallTimeForUnansweredCallsMinutes
	profile["UseMaxConcurrentRedirectedCalls"] = parsed.Command.UseMaxConcurrentRedirectedCalls
	profile["MaxConcurrentRedirectedCalls"] = parsed.Command.MaxConcurrentRedirectedCalls
	profile["UseMaxConcurrentFindMeFollowMeInvocation"] = parsed.Command.UseMaxConcurrentFindMeFollowMeInvocations
	profile["MaxConcurrentFindMeFollowMeInvocations"] = parsed.Command.MaxConcurrentFindMeFollowMeInvocations
	profile["UseMaxFindMeFollowMeDepth"] = parsed.Command.UseMaxFindMeFollowMeDepth
	profile["MaxFindMeFollowMeDepth"] = parsed.Command.MaxFindMeFollowMeDepth
	profile["MaxRedirectionDep"] = parsed.Command.MaxRedirectionDepth

	return profile

}

// GroupCallProcessingModifyPolicyRequest15Sp2 Set Group
func (c client) groupCallProcessingModifyPolicyRequest15Sp2() {
}

// UserCallProcessingGetPolicyRequest21Sp1 Get User
func (c client) userCallProcessingGetPolicyRequest21Sp1(user string) map[string]interface{} {

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

	profile := make(map[string]interface{})

	profile["UseUserCallLimitsSetting"] = parsed.Command.UseUserCallLimitsSetting
	profile["UseMaxSimultaneousCalls"] = parsed.Command.UseMaxSimultaneousCalls
	profile["MaxSimultaneousCalls"] = parsed.Command.MaxSimultaneousCalls
	profile["UseMaxSimultaneousVideoCalls"] = parsed.Command.UseMaxSimultaneousVideoCalls
	profile["MaxSimultaneousVideoCalls"] = parsed.Command.MaxSimultaneousVideoCalls
	profile["UseMaxCallTimeForAnsweredCalls"] = parsed.Command.UseMaxCallTimeForAnsweredCalls
	profile["MaxCallTimeForAnsweredCallsMinutes"] = parsed.Command.MaxCallTimeForAnsweredCallsMinutes
	profile["UseMaxCallTimeForUnansweredCalls"] = parsed.Command.UseMaxCallTimeForUnansweredCalls
	profile["MaxCallTimeForUnansweredCallsMinutes"] = parsed.Command.MaxCallTimeForUnansweredCallsMinutes
	profile["UseMaxConcurrentRedirectedCalls"] = parsed.Command.UseMaxConcurrentRedirectedCalls
	profile["MaxConcurrentRedirectedCalls"] = parsed.Command.MaxConcurrentRedirectedCalls
	profile["UseMaxConcurrentFindMeFollowMeInvocations"] = parsed.Command.UseMaxConcurrentFindMeFollowMeInvocations
	profile["MaxConcurrentFindMeFollowMeInvocations"] = parsed.Command.MaxConcurrentFindMeFollowMeInvocations
	profile["UseMaxFindMeFollowMeDepth"] = parsed.Command.UseMaxFindMeFollowMeDepth
	profile["MaxFindMeFollowMeDepth"] = parsed.Command.MaxFindMeFollowMeDepth
	profile["MaxRedirectionDepth"] = parsed.Command.MaxRedirectionDepth

	return profile
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
	MaxRedirectionDepth int) BroadsoftDocument {

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

	return parsed

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
func (c client) GroupAccessDeviceGetRequest18sp1(enterprise string, group string, device string) map[string]interface{} {

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

	profile := make(map[string]interface{})

	profile["deviceType"] = parsed.Command.DeviceType
	profile["protocol"] = parsed.Command.Protocol
	profile["netAddress"] = parsed.Command.NetAddress
	profile["port"] = parsed.Command.Port
	profile["outboundProxyServerNetAddress"] = parsed.Command.OutboundProxyServerNetAddress
	profile["stunServerNetAddress"] = parsed.Command.StunServerNetAddress
	profile["macAddress"] = parsed.Command.MacAddress
	profile["serialNumber"] = parsed.Command.SerialNumber
	profile["description"] = parsed.Command.Description
	profile["numberOfPorts"] = parsed.Command.NumberOfPorts
	profile["quantity"] = parsed.Command.NumberOfPorts.Quantity
	profile["numberOfAssignedPorts"] = parsed.Command.NumberOfAssignedPorts
	profile["status"] = parsed.Command.Status
	profile["configurationMode"] = parsed.Command.ConfigurationMode
	profile["physicalLocation"] = parsed.Command.PhysicalLocation
	profile["transportProtocol"] = parsed.Command.TransportProtocol
	profile["useCustomUserNamePassword"] = parsed.Command.UseCustomUserNamePassword
	profile["userName"] = parsed.Command.UserName
	profile["version"] = parsed.Command.Version

	return profile

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

func (c client) UserCallForwardingAlwaysGetRequest(user string) map[string]interface{} {

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

	cfaSettings := make(map[string]interface{})

	// user, serviceAssigned, isActive, ForwardToPhoneNumber
	if parsed.Command.RType == "c:ErrorResponse" {
		if strings.Contains(parsed.Command.SummaryEnglish, "[Error 4410]") {
			cfaSettings["serviceAssigned"] = false
			cfaSettings["isActive"] = false
			cfaSettings["forwardToNumber"] = ""
		} else {
			cfaSettings["serviceAssigned"] = false
			cfaSettings["isActive"] = false
			cfaSettings["forwardToNumber"] = ""
		}
	}

	cfaSettings["serviceAssigned"] = true
	cfaSettings["isActive"] = parsed.Command.IsActive
	cfaSettings["forwardToPhoneNumber"] = parsed.Command.ForwardToPhoneNumber

	return cfaSettings
}
