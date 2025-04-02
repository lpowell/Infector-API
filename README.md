<html>
<style>
body {
  background-color: Canvas;
  color: CanvasText;
  color-scheme: light dark;
}    
</style>
</html>

INFECTOR API
---------------

## Table of Contents

- [To-Do](#to-do)
- [Description](#description)
- [Layout](#layout)
    - [Modules](#modules)
        - [Auth](#auth)
        - [Testing](#testing)
        - [Convert](#convert)
        - [Scanner](#scanner)
        - [Operational](#operational)
        - [Endpoint](#endpoint)
    - [Structs](#structs)
    - [Database](#database)
- [Editing](#editing)
    - [New Endpoints/Resources](#new-endpoints/resources)
        - [Adding new modules](#to-integrate-a-new-endpoint-you-will-need-to)
        - [Editing existing modules](#to-intgrate-a-new-resource-in-an-existing-endpoint)
- [Logging](#description)

## To-Do

### Upcoming

- Further decryption schemes
    - AES-CBC
    - RSA
    - ChaCha20
- Endpoint API
    - Install or execute remote scripts from github or other specified sources
    - String analysis for submitted files
- Additional scanners
    - Censys
    - Sandbox services
    - DNS records 
- Further conversion schemes
    - Bxor/Bit flipping
- Swagger page 
- Database diagrams
- Better documentation
- PowerShell API module improvements
- SSL (native or proxy)
- ~~Improvements to error handling and reporting~~
    - ~~API should return functional/usable errors~~
    - ~~StatusCode adjustments~~  
- ~~[Logging improvements](#logging)~~
    - ~~Access Log~~
    - ~~Resource Log~~
    - ~~Transaction Log~~

### Recent Additions

- Logging has been enhanced [Logging improvements](#logging)
- Added a new endpoint for retrieving Github raw files
- Added a resource for [pulling session key expire time](#operational) at `<server>/operational/expire-time`
- Added [AES-GCM decryptor](#convert) to convert endpoint at `<server>/convert/encryption/aesgcm`
- Updated PowerShell API module

## Description

This API is built using [Axum](https://docs.rs/axum/latest/axum/). The database connector uses [SQLx](https://docs.rs/sqlx/latest/sqlx/) and runs on [SQLite](https://www.sqlite.org/). The main purpose is to expose various endpoints and resources behind an authentication scheme. The authentication mechanism uses a user/pass login stored in the local API database. On a valid sign on, an API key is issued with a 30 minute expire time. This key is validated for all endpoints. For example:

A request may look like this:
```JSON
# to <server>/auth/login

{
    "username": "bajiri",
    "password": "1234"
}
```

To which the server will respond with:
```JSON
{
    "api_key": "key",
    "expire_time": "epoch time + 30 minutes from current time"
}
```

This key is then used to access resources and endpoints:
```JSON
# to <server>/testing/hello_world

{
    "api_key": "key"
}
```

On a valid, non-expired key, the server will respond with:
```JSON
{
    "response": "Hello, World!"
}
```

All non authenticated requests will result in a 401 response. Requests to non-existent endpoints will result in a 404 error. 


## Layout

WIP

### Modules

The Infector API uses modules to add features to the webserver. Each endpoint is represented by a routing function in main.rs, which directs the Axum server to a specified module containing the endpoint resources and code. This modular approach makes integrating new endpoints and resources simpler. 

#### Auth

This endpoint is used for generating API keys. A user will need a provisioned account created in the database. Accounts cannot be used to access resources. They can only be used to generate API keys. A session should look like this:

\> USER: Initiates an HTTP request with a valid username and password  
\> SERVER: Validates account credentials and returns a generated API key that is valid for 30 minutes  
\> USER: Accesses endpoints via API key

Currently, the auth endpoint only supports logging in. In the future, there will be resources for checking and extending key expire times.

```JSON
# to <server>/auth/login
{
    "username": "username",
    "password": "password"
}
```

#### Testing

This endpoint is used to test features and confirm that the server is online and functional.

A valid configuration should result in a valid response when submitting the following request:
```JSON
# to <server>/testing/hello_world
{
    "api_key": "key", 
}

# response
{
    "response": "Hello, World!"
}
```

Successful return indicates that the server is functional and their are no issues with key generation or validation.

#### Convert

This endpoint is used for conversions. Encoded content should be sent via a content field in the JSON body. An example request may look like:

```JSON
# to <server>/convert/base64
{
    "api_key": "key",
    "content": "base64 encoded string"
}
```
This will return the decoded content.  

The convert endpoint also supports AES-GCM decryption. This and other resources can be reached with /convert/encryption/.
For example:
```JSON
# to <server>/convert/encryption/aesgcm
{
    "api_key": "key",
    "content": "hex string of encoded content",
    "key": "encryption key",
    "nonce": "12 byte nonce"
}
```
A successful decryption will return the decrypted string. Otherwise, an error will be returned.


#### Scanner

This endpoint is used for interfacing with both local scanners like nmap, as well as remote tools like Censys or Shodan lookups.
This endpoint supports /shodan, /nmap, and /virustotal. 

```JSON
# to <server>/scanner/nmap
{
    "api_key": "key",
    "content": "address to scan"
}
```

In the future, this resource will accept options. Currently, it only supports a default scan.  

#### Operational

This endpoint is used for operational requests, such as listing available endpoints or resources.

```JSON
# to <server>/operational/list
{
    "api_key": "key"
}
```

This will return the time (in epoch) that the current key expires. 

```JSON
# to <server>/operational/expire-time
{
    "api_key": "key"
}
```
#### Endpoint
This API endpoint is for resources that interact with the client. Currently, this is used to send GitHub raw files to the client. It can also be utilized to send local files as well. 

To list available files:
```JSON
# to <server>/endpoint/list
{
    "api_key": "key",
    "content": "list"
}
```

To get the content of a file:
```JSON
# to <server>\endpoint\script
{
    "api_key": "key",
    "content": "short_name"
}
```

### Structs

Public structs are defined in api_structs.rs. 

WIP

### Database

The current database is a SQLite DB operating two tables. A user table for authenticating users and an authentication table that handles generate keys. Key generation is not currently tied to users, but a future update will include a user id for all generated keys, enhancing logging functions. 

## Editing

Editing the API is a simple process. There are minimal steps to adding new endpoints and resources, and templates exist to help speed up development. Modifying the PowerShell API module to include the API modifications should be a straightforward process as well. 

### New Endpoints/Resources

Adding a new endpoint or resource is an easy process. Due to the module style resource scheme, adding a new endpoint simply requires cloning the endpoint_template.rs file and renaming it to the desired endpoint name.  

#### To integrate a new endpoint you will need to:

In the new endpoint module
- Clone the endpoint_template file
- Rename the "resource" route and function to the desired resource name
- Add desired resource code
- Ensure that standards defined in code are met

In Main
- Add the module to the main source
- Add a route in the Axum app routing configuratiuon
- Add a handler
- Follow all standards defined in code


#### To intgrate a new resource in an existing endpoint:

In the existing endpoint module
- Add the desired path into the route function
- Create a new function for the desired resource
- Ensure that all standards defined in code are followed

#### Notes:
- Ensure that the structs utilized in any new resource/endpoint are correct
    - Review api_structs for struct definition
    - You probably want to be using APIContentRequest instead of the default APIRequest



## Logging

Infector API logs to `/var/log/infector_api/*`. It currently creates two log files:
- access.log
- transaction.log

The access log is utilized for tracking connections and resource validation. For example, access log will store the origin IP, headers, and body of every request. It also stores informational logs on account and key validation.

Logging code is located in logger.rs

Example access logs
```text
[2025-04-02 05:22:23.099618396 UTC] [client: <client ip>] [agent: PostmanRuntime/7.43.2] [headers] {"content-type": "application/json", "user-agent": "PostmanRuntime/7.43.2", "accept": "*/*", "postman-token": "6fecc9bd-3160-4a56-99d8-b86871e4aec2", "host": "<host>", "accept-encoding": "gzip, deflate, br", "connection": "keep-alive", "content-length": "55"} [URI] /testing/hello_world [payload] {[required] key: <key> }

[2025-04-02 05:23:13.782334495 UTC] [client: <client ip>] [agent: PostmanRuntime/7.43.2] [headers] {"content-type": "application/json", "user-agent": "PostmanRuntime/7.43.2", "accept": "*/*", "postman-token": "56756d0c-a5a8-4e1c-903e-103add1c7df6", "host": "<host>", "accept-encoding": "gzip, deflate, br", "connection": "keep-alive", "content-length": "55"} [URI] /testing/hello_world [payload] {[required] key: <key> }

[2025-04-02 05:23:13.783410555 UTC] [INFO] API Key validated [key] <key>

[2025-04-02 05:23:15.352422358 UTC] [client: <client ip>] [agent: PostmanRuntime/7.43.2] [headers] {"content-type": "application/json", "user-agent": "PostmanRuntime/7.43.2", "accept": "*/*", "postman-token": "4c91806a-4c12-40d6-926d-ee1de1c7e3da", "host": "<host>", "accept-encoding": "gzip, deflate, br", "connection": "keep-alive", "content-length": "55"} [URI] /testing/hello_world [payload] {[required] key: <key> }

[2025-04-02 05:23:15.353240269 UTC] [INFO] API Key validated [key] <key>
```

Transaction logs mainly hold database logging through a custom tracing subscriber. All `Tracing!` logs are written to the transaction log. 

Example tracing logs
```text
2025-04-02T05:21:55.443726Z DEBUG sqlx::query: summary="PRAGMA foreign_keys = ON; …" db.statement="\n\nPRAGMA foreign_keys = ON; \n" rows_affected=0 rows_returned=0 elapsed=64.046µs elapsed_secs=6.4046e-5
2025-04-02T05:21:55.444348Z  INFO infector_api: Server listening on 0.0.0.0:80
2025-04-02T05:22:20.931696Z DEBUG sqlx::query: summary="PRAGMA foreign_keys = ON; …" db.statement="\n\nPRAGMA foreign_keys = ON; \n" rows_affected=0 rows_returned=0 elapsed=76.665µs elapsed_secs=7.6665e-5
2025-04-02T05:22:20.932375Z  INFO infector_api: Server listening on 0.0.0.0:80
2025-04-02T05:23:12.868036Z DEBUG sqlx::query: summary="PRAGMA foreign_keys = ON; …" db.statement="\n\nPRAGMA foreign_keys = ON; \n" rows_affected=0 rows_returned=0 elapsed=79.749µs elapsed_secs=7.9749e-5
2025-04-02T05:23:12.868679Z  INFO infector_api: Server listening on 0.0.0.0:80
2025-04-02T05:23:13.783166Z DEBUG sqlx::query: summary="SELECT expire_time FROM infector_auth …" db.statement="\n\nSELECT expire_time FROM infector_auth WHERE api_key = ?1\n" rows_affected=0 rows_returned=1 elapsed=374.782µs elapsed_secs=0.000374782
2025-04-02T05:23:13.783351Z  INFO infector_api::testing: API key found, expire_time: 1743571506
2025-04-02T05:23:15.352959Z DEBUG sqlx::query: summary="SELECT expire_time FROM infector_auth …" db.statement="\n\nSELECT expire_time FROM infector_auth WHERE api_key = ?1\n" rows_affected=0 rows_returned=1 elapsed=94.067µs elapsed_secs=9.4067e-5
2025-04-02T05:23:15.353167Z  INFO infector_api::testing: API key found, expire_time: 1743571506
```

At some point, the transaction log will be cleaned up to only log database information. It currently has some temporary logs from earlier logging solutions. 
