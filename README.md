Simple Digital Signing
===========

Just a very simple digital signing concept that uses a client, written in Python, to sign and encrypt a message that is then registered with a RESTful webAPI service, written in C#.

*_Disclaimer:_* This is simply a fun little project and shouldn't be used as a solution for implementing digital signing or encrypting messages between parties.

* Website: [http://www.caffeinatedrat.com](http://www.caffeinatedrat.com)
* Bugs/Suggestions: CaffeinatedRat at gmail dot com

# Client (Python)
The client is a simple implementation written in Python that will attempt to repeatedly register a message with the server at a specific interval.

## Compilation
This script was generated using Python 2.7.6.

## Requirements
This script requires the following libraries.

### Requests library Requests: HTTP for Humans###
* http://docs.python-requests.org/en/latest/
* https://github.com/kennethreitz/requests

### PyCrypto - The Python Cryptography Toolkit###
* Version 2.6.1
* https://www.dlitz.net/software/pycrypto/

# Server (C#) #
The server is a RESTful web API service, written in C#, using Microsoft's API framework and running on IIS.

## Compilation
Requires .NET Framework 4.5.2.
MVC Version 5.2.3.0

## Running the server
IIS7+ is required to run the server.  Although a more adventures individual can get the project running on apache or other non IIS web servers.

### Remote Setup

#### ApplicationHost.config
This can be found in the same directory as the solution file in the folders .vs/config.

Add the following bindings to your site configuration.

    <bindings>
        <binding protocol="http" bindingInformation="<YourIPAddress>:64220:*" />
        <binding protocol="http" bindingInformation="*:64220:localhost" />
    </bindings>

#### Netsh
Using Powershell in administrator mode, allow the binding to have remote access.

    netsh http add urlacl url=http://<YourIPAddress>:64220/ user=everyone

To remove it

    netsh http delete urlacl url=http://<YourIPAddress>:64220/


Change Log
===========

The following contains information about new features, bug fixes, and other version changes.

#### 1.0.0

* Initial Release.
