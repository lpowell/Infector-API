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
- Improvements to error handling and reporting
    - API should return functional/usable errors
    - StatusCode adjustments  
- [Logging improvements](#logging)
    - Access Log
    - Resource Log
    - Transaction Log

### Recent Additions

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

Logging is currently performed with tracing::info!. This records certain database information and transactions. Server logging is done through the console with enhanced logging planned at a later point in development.

Ideally, an access log, resource log, and database log will be utilized. The access log will record web server connections, the resource log will record endpoint operations, and the database log will record transactions.