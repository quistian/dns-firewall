#!/usr/bin/env python

'''

Global Variables convention:
    * start with UpperCase
    * have no _ character
    * may have mid UpperCase words

'''

Debug = True
Silent = True
Verbose = False

CustomerName = 'customer_name'

AuthHeader = {'Content-Type': 'application/json'}
BaseURL = "https://firewall-api.d-zone.ca"
AuthURL = 'https://firewall-auth.d-zone.ca/auth/realms/D-ZoneFireWall/protocol/openid-connect/token'

