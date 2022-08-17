# Authenticating Route Service

This route service authenticates requests before forwarding. Authentication uses [SAP/cloud-security-client-go](https://github.com/SAP/cloud-security-client-go). So it expects to be bound to an instance of Identity service. It authenticates requests with tokens for this instance. 

[![REUSE status](https://api.reuse.software/badge/github.com/dinurp/cf-route-service)](https://api.reuse.software/info/github.com/dinurp/cf-route-service)

## Route Service Overview

This is an experiment based on [cloud foundry sample for route service](https://github.com/cloudfoundry/logging-route-service). 

A route service uses the headers/features that have been added to the GoRouter.
- `X-CF-Forwarded-Url`: A header that contains the original URL that the GoRouter received.
- `X-CF-Proxy-Signature`: A header that the GoRouter uses to determine if a request has gone through the route service.

## Getting Started

- Download this repository 
- Create a service instance of Identity Service. 
```
cf create-service identity application IDENTITY-SERVICE -c ias-config.json
```
`IDENTITY-SERVICE` is a name for the service
- Push the app to your space in SAP BTP, Cloud Foundry runtime.
```
cf push --no-start
```
- Bind the service to the identity service instance created earlier.
```
cf bind-service auth-route-service IDENTITY-SERVICE
```
- Create a user-provided route service ([see docs](http://docs.cloudfoundry.org/services/route-services.html#user-provided))
```
cf create-user-provided-service SERVICE-INSTANCE -r ROUTE-SERVICE-URL 
```
`ROUTE-SERVICE-URL` is the url of the app

`SERVICE-INSTANCE` is a name for the user-provided service

- Push your app which needs to be guarded with the route service. For example:
```
cf push echo --no-manifest --random-route -m 1M -k 128M -o ealen/echo-server
```
This app does not authenticate requests.
```
curl APP-URL 
```
`APP-URL` is the url of the app to be guarded.
- Bind the route service to the route (domain/hostname)
```
cf bind-route-service DOMAIN SERVICE-INSTANCE [--hostname HOSTNAME]
```
- Now the app requires authentication.
```
curl APP-URL 
```

- Fetch a token for the identity service and request again.
```
curl APP-URL -H -H "Authorization: bearer $token"
```
`$token` is the token from identity service

*Note:* The route service authenticates `xsuaa` tokens if bound to an xsuaa instance. 

## Testing

[demo.http](./demo.http) has sample requests to verify that requests are passed on to the server correctly. 
The script is is for [httpyac](https://httpyac.github.io/guide/variables.html#oauth2-openid-connect). An environment file needs to be 
setup for enable the httpyac to retrieve token from SAP Identity Services. The values can be copied from a key `IDENTITY-SERVICE`
```
cf create-service-key IDENTITY-SERVICE key
cf service-key IDENTITY-SERVICE key
```
A sample [environment definition](https://httpyac.github.io/guide/environments.html#dotenv) like below needs to be provided for example in a file named `.env`.
```
oauth2_clientId="--clientid from key--"
oauth2_clientSecret="---clientsecret from key---"
oauth2_url="--url from key---"
oauth2_tokenEndpoint="{{oauth2_url}}/oauth2/token"
oauth2_authorizationEndpoint="{{oauth2_url}}/oauth2/authorize"

app_url="APP_URL"
```
Once environment is setup like above, requests can be executed in `Visual Studio Code` using [httpyac plugin](https://httpyac.github.io/guide/installation_vscode.html) or from [Command Line Interface](https://httpyac.github.io/guide/installation_cli.html).

## Environment Variables

### SKIP_SSL_VALIDATION

Set this environment variable to true in order to skip the validation of SSL certificates.
By default the route service will attempt to validate certificates.

Example:

```sh
cf set-env auth-route-service SKIP_SSL_VALIDATION true
cf restart auth-route-service
```
