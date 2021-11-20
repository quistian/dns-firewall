#!/usr/bin/env python

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

'''

RESTful Python API to D-ZONE DNS Firewall

Schema documentation:

    https://firewall-api.d-zone.ca/assets/lib/swagger-ui/index.html?url=%2Fswagger.json#/

ToDo:
    look at request_oauth 

'''

import json
import os
import requests
import sys

from pprint import pprint
from cira_am import config

def generic_request(method, url, headers={}, params={}, data={}):
    fn = 'api.generic_request'
    if config.Debug:
        print('func: {} method: {} url: {} \n'.format(fn, method, url))
    try:
        if method == 'DELETE':
            resp = requests.delete(url, headers=headers)
        else:
            resp = requests.request(method, url, headers=headers, params=params, data=data, timeout=5)
        resp.raise_for_status()
        if resp.status_code == 204:
            return resp.text
        else:
            return resp.json()
    except requests.exceptions.HTTPError as errh:
        print(errh)
        print('Request Text: ', resp.text)
        exit()
    except requests.exceptions.ConnectionError as errc:
        print(errc)
        exit()
    except requests.exceptions.Timeout as errt:
        print(errt)
        exit()
    except requests.exceptions.RequestException as err:
        print(err)
        exit()

# Authentication Token Routines

'''

curl -X POST \
    -d "client_id=<your customer name> & \
        client_secret=<your client secret> & \
        grant_type=password& \
        username=<username>& \
        password=<user password>&  \
        totp=<one time code>" \
https://firewall-auth.d-zone.ca/auth/realms/D-ZoneFireWall/protocol/openid-connect/token

resp =
{
    'access_token': 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqMD...',
    'expires_in': 300, // Access tokens are good for 5 minutes
    'not-before-policy':0,
    'refresh_expires_in': 1800, // Refresh tokens are good for 30 minutes
    'refresh_token': 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4YW...',
    'scope':'Customer_API_Client_Template'
    'token_type':'Bearer',
    'session_state':'0e82a3e6-1160-42c5-b7d0-8271e32782e3',
}

'''

def fetch_fresh_tokens(creds):
    fn = 'api.fetch_fresh_tokens'
    URL = config.AuthURL

    vals = generic_request('POST', URL, data=creds)
#   resp = requests.post(URL,  data=creds)
#   vals = resp.json()
    return vals

'''

curl –X POST -d \
    "client_id=<your customer name>&
    client_secret=<clientsecret>
    grant_type=refresh_token
    refresh_token=<refresh_token>" \
    https://firewall-auth.d-zone.ca/auth/realms/D-ZoneFireWall/protocol/openid-connect/token

Response:

{
'access_token': '<very long string>',
'expires_in': 300, // Access tokens are good for 5 minutes
'refresh_expires_in': 1800, // Refresh tokens are good for 30 minutes
'refresh_token': '<very long string>',
'token_type': 'bearer',
'id_token': '<very long long string>'
'not-before-policy': <a Unix timestamp>,
'session_state': '<session id>'
}

'''

def fetch_refresh_tokens(creds):
    fn = 'api.refresh_tokens'
    URL = config.AuthURL
    vals = generic_request('POST', URL, data=creds)
    if config.Debug:
        print('fn: {} refreshing tokens'.format(fn))
        print('Input creds data: {}'.format(creds))
        print('Refresh response: {}'.format(vals))
    return vals

# Threat Feeds Section

'''

GET /threatfeeds - params {}

JSON response:

    [
      {
        "id": 0,
        "name": "string",
        "description": "string",
        "defaultEnable": true
      }
    ]

'''

def get_threatfeeds():
    fn = 'get_threatfeeds'
    URL = config.BaseURL + '/threatfeeds'
    vals = generic_request('GET', URL)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))
    return vals

# Customer Account Information

'''

GET /customers  Search for Customer Information

Parameters:

    type string Customer type one of ADMIN, RESELLER, STANDARD
    name string Customer name
    apiAccess boolean Customer API access feature enabled or not
    status string Customer status  one of ACTIVE, TRIAL, COMPLIMENTARY, TO_BE_DISABLED
    sortColumn string Sort by column (name, type)
    sortOrder string Sorting order (asc, desc)
    pageSize integer($int32) Number of results per page
    page integer($int32) Page number

JSON Response

    {
      "hasNext": true,
      "hasPrevious": true,
      "page": 0,
      "items": [
        {}
      ],
      "totalRowCount": 0,
      "totalPageCount": 0,
      "currentRowCount": 0
    }

Items data structure:

id    	integer($int64) The unique identifier in the system for the entity
name    string Customer name
type    string Type of customer
Enum: Array [ 3 ]
parentCustomerPkid    integer($int64) Optional reseller id indicating if the customer was created by a reseller customer
parentCustomerName    string Optional reseller name indicating if the customer belong to a parent reseller customer
networkUsers    integer($int32) Number of network users a customer has
wifiPoints    integer($int32) Number of WiFi access points a customer has
status    string Customer's status, ie. Trial/Active
Enum: Array [ 4 ]
statusSince    string($date-time) Date since last status update
trafficCount    integer($int64) Daily traffic count in QPS
segmentPkid    integer($int64) Pkid of segment that customer belongs to
managed    boolean Flag to indicate if the customer is managed by service provider
features


'''

def search_customers(name):
    fn = 'search_customers'
    URL = config.BaseURL + '/customers'
    params = {
        'type': 'STANDARD',
        'name': 'university of toronto'
    }
    resp = requests.get(URL, headers=config.AuthHeader, params=params) 
    vals = resp.json()
#   vals = generic_request('GET', URL, headers=config.AuthHeader, params=params)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))
    return vals

def get_customer_by_id(id):
    fn = 'get_customer_by_id'
    URL = config.BaseURL + '/customers/' + str(id)
#   vals = generic_request('GET', URL, headers=config.AuthHeader)
    resp = requests.get(URL, headers=config.AuthHeader)
    vals = resp.json()
    if config.Debug:
        print('func: {} header used: {}'.format(fn, config.AuthHeader))
        print('func: {} URL used: {}'.format(fn, resp.url))
        print('func: {} Response text: {}'.format(fn, resp.text))
        print('func: {} return data: {}'.format(fn, vals))
    return vals

def domainlookup(node):
    fn = 'domainlookup'
    URL = config.BaseURL + '/domainlookup'
    payload = {'node': node, 'type': 'fqdn'}
    vals = generic_request('POST', URL, payload=payload)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))
    return vals

'''
Fetching Account Information

Request:  GET /account  no Parameters required

JSON response:

{'accountName': 'university of toronto',
 'features': {'apiAccess': True,
              'contentFilter': True,
              'domainOverride': False,
              'feedPermissions': [{'enable': True, 'threatFeedName': 'CCCS'},
                                  {'enable': True,
                                   'threatFeedName': 'Cybertip'},
                                  {'enable': True,
                                   'threatFeedName': 'CanSSOC'}],
              'urlFilter': True},
 'secret': None}

'''

def get_account_info():
    fn = 'get_account_info'
    URL = config.BaseURL + '/account'
    vals = generic_request('GET', URL)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))    
    return vals


'''
Get a list of all Users

Payload Data
email string (query) User email
customerId integer($int64) (query) Customer ID
username string (query) User name
name string (query) User name
sortColumn string (query) Sort by column (username, customerName, email)
sortOrder string (query) Sorting order (asc, desc)
pageSize integer($int32) (query) Number of results per page
page integer($int32) (query) Page number
id integer($int64) (query)
'''

def get_users():
    fn = 'get_users'
    URL = config.BaseURL + '/users'

    vals = generic_request('GET', URL)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))    
    return vals


'''

Get Blockpages

GET query Parameters: (all optional)
    customerId (int64) Customer ID
    name (string) Block page name
    sortColumn (string) Sort by column (name, customer)
    sortOrder (string) Sorting order (asc, desc)
    pageSize (int32) Number of results per page
    page (int32) Page number
    id (int64) Block page ID

JSON response:

{
'hasNext': False,
'hasPrevious': False,
'page': 0,
'items': [ {
    'id': 173,
    'name': 'utoronto_blockpage-155',
    'customerId': 171,
    'customerName': 'university of toronto',
    'data': {
        'branding': {
            'tagline': 'DNS Firewall',
            'color': '#3ca2bc'
        },
        'webFiltering': {
            'showBlockReason': True,
            'blockReasonMessage': 'This site has been blocked by the CIRA D-Zone DNS Firewall Service',
            'provideAdminContacts': True,
            'adminContactEmail': 'security@utoronto.ca',
            'adminContactPhone': '+1 416 978 4621'
        },
        'malware': {
            'showBlockReason': True,
            'blockReasonMessage': 'This site has been blocked by the CIRA D-Zone DNS Firewall Service\nThis site is known for Malware and/or Phishing',
            'provideAdminContacts': True,
            'adminContactEmail': 'security@utoronto.ca',
            'adminContactPhone': '+1 416 978 4621'
        }
    },
    'networkIdNames': {
        '9904': 'dns1',
        '4210': 'eis netdev',
        '10181': 'utsc',
        '9944': 'dns5',
        '8907': 'dns8',
        '8908': 'dns9',
        '9855': 'dns4'
    }
    } ],
    'totalRowCount': 1,
    'totalPageCount': 1,
    'currentRowCount': 1
    }

'''

def get_blockpages():
    fn = 'get_blockpages'
    URL = config.BaseURL + '/blockpages'
    vals = generic_request('GET', URL)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))    
    return vals
    
# Profiles Section

'''
Get Profile Filterblocks

method -> GET
path -> /profiles/filterblocks
params -> None

JSON response:

{
'all': ['sb-crime', 'sb-self-harm', 'sb-child-abuse', 'sb-porn', ... ]
'light': ['sb-self-harm', 'sb-child-abuse', 'sb-crime'],
'medium': ['sb-gambling', 'sb-hacking', 'sb-nudity', ... ]
'strict': ['sb-gambling', 'sb-hacking', 'sb-nudity', ... ]
}

'''

def get_profiles_filterblocks():
    fn = 'get_profiles_filterblocks'
    URL = config.BaseURL + '/profiles/filterblocks'
    vals = generic_request('GET', URL)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))    
    return vals


'''
Get Profile by ID

method -> GET
path -> /profiles/{Id}
params -> {}

JSON response:

{
    'id': 14739,
    'name': 'dns1-profile',
    'customerId': 171,
    'customerName': 'university of toronto',
    'data': {
        'temporarilyDisabled': False,
        'internetSecurity': {
            'safeSearchServices': { 'BING': False, 'GOOGLE': False, 'YOUTUBE': False },
            'enableMalwareProtection': True
        },
        'webFilterLevel': { 'level': 'none', 'blockList': [] },
        'internetOffSchedule': { 'enabled': False, 'schedules': [] },
        'contentRestriction': { 'enabled': False, 'schedules': [], 'blockList': [] },
        'urlFilter': {
            'allowList': [],
            'blockList': [
                {'node': '34as5rd6tfyg.cabanova.com', 'type': 'naked-host-path' },
                {'node': '3ccacb54.sibforms.com', 'type': 'naked-host-path'},
                ,,,
            ],
            'blackList': [
                {'node': '34as5rd6tfyg.cabanova.com', 'type': 'naked-host-path'},
                {'node': '3ccacb54.sibforms.com', 'type': 'naked-host-path'},
                ...
                ]
            'whiteList': [],
              }
            },
    'networkIdNames': {'9904': 'dns1'},
    'feedSubscriptions': [
        {'threatFeedName': 'CCCS', 'active': True},
        {'threatFeedName': 'Cybertip', 'active': True},
        {'threatFeedName': 'CanSSOC', 'active': True}
    ]
}

'''

def get_profile_by_id(pid):
    fn = 'get_profile_by_id'
    URL = config.BaseURL + '/profiles/' + str(pid)
    vals = generic_request('GET', URL, headers=config.AuthHeader)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, pprint(vals)))   
    return vals
    
'''
Update and existing profile given a profileID and a new structure

method -> PUT
url -> /profiles/{id}
body -> profile schema

JSON response

updated profile schema

'''

def put_profile(pid, data_struct):
    fn = 'api.put_profile'
    URL = config.BaseURL + '/profiles/' + str(pid)
    payload = json.dumps(data_struct)
    vals = generic_request('PUT', URL, headers=config.AuthHeader, data=payload)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))
    return vals    

'''
Search Profiles

method -> GET
path -> //profiles

Parameters: (All Optional)
    customerId integer($int64) Customer ID
    name string Profile name
    sortColumn string Sort by column (name, customerName)
    sortOrder string Sorting order (asc, desc)
    pageSize integer($int32) Number of results per page
    page integer($int32)

JSON response:
    
    A list, pages of profile schemas

'''

def search_profiles(name):
    fn = 'search_profiles'
    URL = config.BaseURL + '/profiles'

    vals = generic_request('GET', URL, headers=config.AuthHeader, params={'name': name})
    if config.Debug:
        print('func: {} searching for substr {} returns {}'.format(fn, name, vals))    
    return vals

'''
Create a new profile

method -> POST
url -> /profiles/
params -> {}
body -> json schema of new profile

A profile can be created without any networks attached

'''

def create_profile(prof):
    fn = 'create_profile'
    URL = config.BaseURL + '/profiles'

    vals = generic_request('POST', URL, headers=config.AuthHeader, data=json.dumps(prof))
    if config.Debug:
        print('func: {} creating profile {} returns {}'.format(fn, prof['name'], vals))    
    return vals

'''
Delete an existing profile

method -> DELETE
url -> /profiles/id
params -> {}

Response -> https status == 204

'''

def delete_profile(pid):
    fn = 'profile_delete'
    URL = config.BaseURL + '/profiles/' + str(pid)
    vals = generic_request('DELETE', URL, headers=config.AuthHeader)
    if config.Debug:
        print('func: {} deleting profile ID {} returns {}'.format(fn, pid, vals))    
    return vals

# Networks Section

'''

Search networks for a given value

method -> GET
url -> /networks
parameters ->
{
name: string Network name
ip: string IP Address
customerId: integer($int64) Customer ID
parentCustomerId: integer($int64) Parent Customer ID
time_zone: string Time Zone
sortColumn: string Sort by column (name, customerName, profileName, blockPageName, timeZone)
sortOrder: string Sorting order (asc, desc)
pageSize: integer($int32) Number of results per page
page: integer($int32) Page number
}

All optional

Json response

items is a list of dictionares of networks

{
'hasNext': False,
'hasPrevious': False,
'page': 0,
'items': [
    {
    'id': 9904,
    'name': 'dns1',
    'subscriberId': 'dns1-f6850bd8-6fa2-44a3-81b9-9cd101c0c46d',
    'timeZone': 'America/Toronto',
    'customerId': 171,
    'ipAddresses': [ {
        'id': 22618, 
        'address': '128.100.100.128',
        'type': 'V4',
        'networkId': 9904,
        'dynamicSourceAddressId': None,
        'childIPV4': None,
        'childIPV6': None,
        'lastChecked': None }],
    'customerName': 'university of toronto',
    'profileId': 14739,
    'profileName': 'dns1-profile',
    'blockPageId': 173,
    'blockPageName': 'utoronto_blockpage-155',
    'reportEmails': None,
    'reportFrequency': 'NEVER'
    },
    etc...
    {
    'id': 10181,
    'name': 'utsc',
    'subscriberId': 'utsc-173f340a-a4a5-4514-a00c-028de99ca7ea',
    'timeZone': 'America/Toronto',
    'customerId': 171,
    'ipAddresses': [
        {
        'id': 23134,
        'address': '142.1.166.107', 'type': 'V4', 'networkId': 10181,
        'dynamicSourceAddressId': None, 'childIPV4': None, 'childIPV6': None,
        'lastChecked': None
        }
        ],
    'customerName': 'university of toronto',
    'profileId': 15179,
    'profileName': 'utsc-profile',
    'blockPageId': 173, 'blockPageName': 'utoronto_blockpage-155',
    'reportEmails': None,
    'reportFrequency': 'DAILY'
    }
    ],
'totalRowCount': 7,
'totalPageCount': 1,
'currentRowCount': 7
}


'''

def search_networks(name=None, ip=None):
    fn = 'api.get_networks'
    URL = config.BaseURL + '/networks'
    payload = {}
    if name:
        payload['name'] = name
    if ip:
        payload['ip'] = ip
    vals = generic_request('GET', URL, headers=config.AuthHeader, params=payload)
    if config.Debug:
        print('func: {} return data:'.format(fn))
        pprint(vals)   
    return vals

'''
Get networks by Id

method -> GET
url -> /networks/{Id}
params -> {}

    Error if network Id does not exist:
    https error code: 404
    URL:  https://firewall-api.d-zone.ca/networks/101
    Reason:  Not Found
    Body:  None
    Request Text:  {"errors":{"NETWORK_DOES_NOT_EXIST":null}}

'''

def get_network_by_id(nid):
    fn = 'api.get_network_by_id'
    URL = config.BaseURL + '/networks/' + str(nid)
    vals = generic_request('GET', URL, headers=config.AuthHeader)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))   
    return vals

'''

Update a given network

method -> PUT
url -> /networks/id
params -> {}
body -> json network schema

Response:
    Success: https status code: 200
    Data: json network schema of updated network

'''

def put_network(net_id, net_data_struct):
    fn = 'api.put_network'
    URL = config.BaseURL + '/networks/' + str(net_id)
    payload = json.dumps(net_data_struct)
    vals = generic_request('PUT', URL, headers=config.AuthHeader, data=payload)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))
    return vals    

'''

Delete an existing network

method -> DELETE
url -> /networks/id
params -> {}

Response -> https status == 204

'''

def delete_network(netid):
    fn = 'api.delete_network'
    URL = config.BaseURL + '/networks/' + str(netid)
    vals = generic_request('DELETE', URL, headers=config.AuthHeader)
    if config.Debug:
        print('func: {} deleting network ID {} returns {}'.format(fn, netid, vals))    
    return vals

'''
Create a new network

method -> POST
url -> /networks/
params -> {}
body -> json schema of new profile

https session returns status: 204 upon success
'''

def create_network(net):
    fn = 'api.create_network'
    URL = config.BaseURL + '/networks'

    vals = generic_request('POST', URL, headers=config.AuthHeader, data=json.dumps(net))
    if config.Debug:
        print('func: {} creating network {} returns {}'.format(fn, net['name'], vals))    
    return vals

'''
returns a list of Time Zones
zones = ['Africa/Abidjan', 'Africa/Accra', 'Africa/Addis_Ababa', 'Africa/Algiers
', 'Africa/Asmara', 'Africa/Asmera', 'Africa/Bamako', 'Africa/Bangui', 'Africa/B
anjul', 'Africa/Bissau', 'Africa/Blantyre', 'Africa/Brazzaville', 'Africa/Bujumb
ura', 'Africa/Cairo', 'Africa/Casablanca', 'Africa/Ceuta', 'Africa/Conakry', 'Af
rica/Dakar', 'Africa/Dar_es_Salaam', 'Africa/Djibouti', 'Africa/Douala', 'Africa
/El_Aaiun', ... ]
'''
def get_timezones():
    fn = 'get_timezones'
    URL = config.BaseURL + '/networks/timezones'

    vals = generic_request('GET', URL)
    if config.Debug:
        print('func: {} return data: {}'.format(fn, vals))   
    return vals
    
