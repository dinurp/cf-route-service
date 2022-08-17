// SPDX-FileCopyrightText: 2022 2022 Dinu Pavithran <dinu.pavithran@yahoo.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/sap/cloud-security-client-go/env"
)

type VCAPServices struct {
	Xsuaa []struct {
		Credentials XsuaaCredentials `json:"credentials"`
	} `json:"xsuaa"`
}

type XsuaaCredentials struct {
	ClientID  string `json:"clientid"`
	Domain    string `json:"uaadomain"`
	XsAppName string `json:"xsappname"`
	Key       string `json:"verificationkey"`
}

const vcapServicesEnvKey = "VCAP_SERVICES"

func getAuthConfig() (env.Identity, error) {
	vcapServicesString := os.Getenv(vcapServicesEnvKey)
	var vcapServices VCAPServices
	err := json.Unmarshal([]byte(vcapServicesString), &vcapServices)
	if err != nil {
		return nil, fmt.Errorf("cannot parse vcap services: %w", err)
	}
	if len(vcapServices.Xsuaa) == 0 {
		config, err := env.ParseIdentityConfig()
		if err != nil {
			return nil, fmt.Errorf("no 'xsuaa' service instance bound to the application, %s", err.Error())
		}
		return config, nil
	}
	if len(vcapServices.Xsuaa) > 1 {
		return nil, fmt.Errorf("more than one 'xsuaa' service instance bound to the application. This is currently not supported")
	}
	return &vcapServices.Xsuaa[0].Credentials, nil
}

// GetClientID implements the env.Identity interface.
func (c XsuaaCredentials) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the env.Identity interface.
func (c XsuaaCredentials) GetClientSecret() string {
	return ""
}

// GetURL implements the env.Identity interface.
func (c XsuaaCredentials) GetURL() string {
	return ""
}

// GetDomains implements the env.Identity interface.
func (c XsuaaCredentials) GetDomains() []string {
	domains := []string{c.Domain}
	return domains
}

// GetZoneUUID implements the env.Identity interface.
func (c XsuaaCredentials) GetZoneUUID() uuid.UUID {
	return uuid.Nil
}

// GetProofTokenURL implements the env.Identity interface.
func (c XsuaaCredentials) GetProofTokenURL() string {
	return ""
}

// GetOsbURL implements the env.Identity interface.
func (c XsuaaCredentials) GetOsbURL() string {
	return ""
}

// GetCertificate implements the env.Identity interface.
func (c XsuaaCredentials) GetCertificate() string {
	return ""
}

// IsCertificateBased implements the env.Identity interface.
func (c XsuaaCredentials) IsCertificateBased() bool {
	return false
}

// GetKey implements the env.Identity interface.
func (c XsuaaCredentials) GetKey() string {
	return c.Key
}

// GetCertificateExpiresAt implements the env.Identity interface.
func (c XsuaaCredentials) GetCertificateExpiresAt() string {
	return ""
}
