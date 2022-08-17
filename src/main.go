// SPDX-FileCopyrightText: 2022 2022 Dinu Pavithran <dinu.pavithran@yahoo.com>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"

	"github.com/sap/cloud-security-client-go/auth"
)

const (
	DEFAULT_PORT            = "8080"
	CF_FORWARDED_URL_HEADER = "X-Cf-Forwarded-Url"
)

func main() {
	config, err := getAuthConfig()
	if err != nil {
		panic(err)
	}
	authMiddleware := auth.NewMiddleware(config, auth.Options{})

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = DEFAULT_PORT
	}
	skipSslValidation, _ := strconv.ParseBool(os.Getenv("SKIP_SSL_VALIDATION"))
	transport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipSslValidation},
	}
	log.SetOutput(os.Stdout)
	log.SetPrefix("[auth-proxy] ")

	proxy := NewAuthProxy(authMiddleware, &transport)

	log.Printf("Listening on port %q", port)
	http.ListenAndServe(":"+port, proxy)
}

func NewAuthProxy(m *auth.Middleware, transport *http.Transport) http.Handler {
	next := &httputil.ReverseProxy{
		Director: func(req *http.Request) {

			forwardedURL := req.Header.Get(CF_FORWARDED_URL_HEADER)
			// Note that url.Parse is decoding any url-encoded characters.
			url, err := url.Parse(forwardedURL)
			if err != nil {
				log.Printf("Error parsing forwarded URL: %q", err.Error())
				req.Host = ""
				req.URL = nil
			} else {
				req.URL = url
				req.Host = url.Host
			}
		},
		Transport: transport,
	}

	// this authenticates a request
	// it deletes the Authorization header before forwarding the request
	// it does not enrich the context.
	// so m.HandlerFunc which does is not used

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := m.Authenticate(r)

		if err != nil {
			log.Printf("Authentication failed: %q", err.Error())
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		r.Header.Del("authorization")

		// Continue serving http if token was valid
		next.ServeHTTP(w, r)
	})

}
