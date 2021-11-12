#!/usr/bin/env python

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

'''

RESTful Python API to D-ZONE DNS Firewall

'''

import os
import sys
import json
import requests

from pprint import pprint

Debug = 0
Debug = 1


Auth_Header = {'Content-Type': 'application/json'}

BaseURL = "https://firewall-api.d-zone.ca"
BaseAuthURL = "https://firewall-auth.d-zone.ca"

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
"access_token":
    "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqMDdsUnhMYXp
    jaktyTS1QcjMtV0JrS2l4bzZ3bFpmV2pVUXhGUHB6OFNjIn0.eyJleHAiOjE2MzY0ODM3NzgsImlhdCI
    6MTYzNjQ4MzQ3OCwianRpIjoiYTg5MDliYzctMmQwMy00ZWZiLThmOTAtYWJhNjVhYTk4YWNjIiwiaXN
    zIjoiaHR0cHM6Ly9maXJld2FsbC1hdXRoLmQtem9uZS5jYS9hdXRoL3JlYWxtcy9ELVpvbmVGaXJlV2F
    sbCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJmOGNmMTNjNS01YzhmLTQ0NGQtYTMxNy05MWYzYjE0MmE
    xN2MiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ1bml2ZXJzaXR5IG9mIHRvcm9udG8iLCJzZXNzaW9uX3N
    0YXRlIjoiMGU4MmEzZTYtMTE2MC00MmM1LWI3ZDAtODI3MWUzMjc4MmUzIiwiYWNyIjoiMSIsInJlYWx
    tX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwicmV
    hZC1vbmx5IiwiZnVsbC1hY2Nlc3MiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGV
    zIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX1
    9LCJzY29wZSI6IkN1c3RvbWVyX0FQSV9DbGllbnRfVGVtcGxhdGUiLCJ1aWQiOiJ1bml2ZXJzaXR5IG9
    mIHRvcm9udG8ifQ.Fa1ZazjoYEC8mGcfj7QiIpDekRx02USeGP3DIgLo9wjCB2kslVCSeZOW7BUuTaK8
    _7FeikT6lkPqV45xoOtJhE1O0ck6NRMgAdMNL1ffz5tGc8jTi3kYtrgVfoOTPtX-ES0HmvO5Qpkvmqws
    vKR6VmvQ2ys86gxCZ9Tmqae8urOdsHHdjO_Rzjgxk6mxdntFAapsIFChRoOJpLMEkK9KRA7l4W6egmTT
    sUmNJS1rV7vg5Akgnwl0Q9K6dbkUilIW74NyMtJlTUR3x6NSSuGs_VXcVbvFi0GM1eOYMQ6UEg9beAWo
    wrpMLyhcpi2gAd_XQpePk0HJQDYMsJM2eiNQDQ",
"expires_in": 300,
"refresh_expires_in": 1800,
"refresh_token":
    "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4YWQ0Zjgw
    OS00MTkyLTQ0YjgtYmMyNi1kMjc3NmU3MTA1NDEifQ.eyJleHAiOjE2MzY0ODUyNzgsImlhdCI6MTYzN
    jQ4MzQ3OCwianRpIjoiOTI4YjdkMzktNWIwOS00ODkwLTg4NGYtY2UyNTc2NjVhZmZkIiwiaXNzIjoia
    HR0cHM6Ly9maXJld2FsbC1hdXRoLmQtem9uZS5jYS9hdXRoL3JlYWxtcy9ELVpvbmVGaXJlV2FsbCIsI
    mF1ZCI6Imh0dHBzOi8vZmlyZXdhbGwtYXV0aC5kLXpvbmUuY2EvYXV0aC9yZWFsbXMvRC1ab25lRmlyZ
    VdhbGwiLCJzdWIiOiJmOGNmMTNjNS01YzhmLTQ0NGQtYTMxNy05MWYzYjE0MmExN2MiLCJ0eXAiOiJSZ
    WZyZXNoIiwiYXpwIjoidW5pdmVyc2l0eSBvZiB0b3JvbnRvIiwic2Vzc2lvbl9zdGF0ZSI6IjBlODJhM
    2U2LTExNjAtNDJjNS1iN2QwLTgyNzFlMzI3ODJlMyIsInNjb3BlIjoiQ3VzdG9tZXJfQVBJX0NsaWVud
    F9UZW1wbGF0ZSJ9.5f965evRaT-fkTkLmrrcAeTCzfJ1f2hK3cNpfn_lgh8",
"token_type":"Bearer",
"not-before-policy":0,
"session_state":"0e82a3e6-1160-42c5-b7d0-8271e32782e3",
"scope":"Customer_API_Client_Template"
}

'''

def dnsfirewall_init():
    global expiry_ttl, refresh_tok
    global Auth_Header

    uname = os.environ['CLIENT_UID']
    pw = os.environ['CLIENT_PW']
    client_id = os.environ['CLIENT_ID']
    secret_key = os.environ['SECRET_KEY']

    URL = BaseAuthURL + '/auth/realms/D-ZoneFireWall/protocol/openid-connect/token/'

    header = { 'Content-Type': 'application/json' }

    creds = {
        'client_id': client_id,
        'client_secret': secret_key,
        'grant_type': 'password',
        'username': uname,
        'password': pw,
    }

    req = requests.post(URL, data=creds)
    vals = json.loads(req.text)

    access_tok = vals['access_token']
    refresh_tok = vals['refresh_token']
    tok_lifetime = vals['expires_in']
    refresh_tok_lifetime = vals['refresh_expires_in'],
    tok_type = vals['token_type']
    not_before_policy = vals['not-before-policy']
    session_state = vals['session_state']
    refresh_tok = vals['refresh_token']
    scope = vals['scope']
    Auth_Header['Authorization'] =  tok_type + ' ' + access_tok
    return access_tok

def get_threatfeeds():
    URL = BaseURL + '/threatfeeds'
    req = requests.get(URL, headers=Auth_Header)
    vals = json.loads(req.text)
    pprint(vals)
    return vals

'''

JSON response:

{
'total': 1,
'limit': 1,
'content': [
    {'name': 'sb-data-prot',
    'description': 'Information Security'
    }]
}

'''

def domainlookup(node):
    URL = BaseURL + '/domainlookup'
    payload = {'node': node, 'type': 'fqdn'}
    req = requests.post(URL, headers=Auth_Header, json=payload)
    vals = json.loads(req.text)
    print(vals)
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
    URL = BaseURL + '/account'
    req = requests.get(URL, headers=Auth_Header)
    vals = json.loads(req.text)
    pprint(vals)
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
    URL = BaseURL + '/users'

    req = requests.get(URL, headers=Auth_Header)
    vals = json.loads(req.text)
    print(vals)

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
    URL = BaseURL + '/blockpages'

    payload = {}
    req = requests.get(URL, headers=Auth_Header, params=payload)
    vals = json.loads(req.text)
    print(vals)

'''
Get Profile Filterblocks

GET params -> None

JSON response:

{
'all':
    ['sb-crime', 'sb-self-harm', 'sb-child-abuse', 'sb-porn',
    'sb-cults', 'sb-nudity', 'sb-lingerie', 'sb-sex-education',
    'sb-offensive', 'sb-hacking', 'sb-cheating', 'sb-anonymizers',
    'sb-translate', 'sb-dating', 'sb-drugs', 'sb-alc-tob', 'sb-software',
    'sb-p2p', 'sb-warez', 'sb-gambling', 'sb-shopping', 'sb-entertainment',
    'sb-politics', 'sb-weapons', 'sb-violence', 'sb-hate', 'sb-webmail',
    'sb-games', 'sb-forums', 'sb-community', 'sb-chat', 'sb-streaming',
    'sb-ads', 'sb-arts', 'sb-business', 'sb-data-prot', 'sb-edu',
    'sb-errors', 'sb-fashion', 'sb-food', 'sb-gov', 'sb-greet',
    'sb-health', 'sb-images', 'sb-jobs', 'sb-money', 'sb-news',
    'sb-nonprof', 'sb-parked', 'sb-realty', 'sb-recreation', 'sb-religion',
    'sb-rfc1918', 'sb-search', 'sb-sports', 'sb-tech', 'sb-travel',
    'sb-vehicles'],
'light':
    ['sb-self-harm', 'sb-child-abuse', 'sb-crime'],
'medium':
    ['sb-gambling', 'sb-hacking', 'sb-nudity',
    'sb-drugs', 'sb-translate', 'sb-software', 'sb-offensive',
    'sb-self-harm', 'sb-cheating', 'sb-weapons', 'sb-shopping', 'sb-cults',
    'sb-sex-education', 'sb-p2p', 'sb-anonymizers', 'sb-porn',
    'sb-child-abuse', 'sb-crime', 'sb-violence', 'sb-dating', 'sb-warez',
    'sb-hate', 'sb-entertainment', 'sb-lingerie', 'sb-alc-tob',
    'sb-politics'],
'strict':
    ['sb-gambling', 'sb-hacking', 'sb-nudity',
    'sb-drugs', 'sb-translate', 'sb-software', 'sb-offensive', 'sb-webmail',
    'sb-self-harm', 'sb-cheating', 'sb-weapons', 'sb-games', 'sb-shopping',
    'sb-cults', 'sb-sex-education', 'sb-p2p', 'sb-anonymizers',
    'sb-forums', 'sb-porn', 'sb-child-abuse', 'sb-crime', 'sb-violence',
    'sb-dating', 'sb-community', 'sb-warez', 'sb-hate', 'sb-chat',
    'sb-entertainment', 'sb-lingerie', 'sb-alc-tob', 'sb-politics']
}

'''

def get_profiles_filterblocks():
    URL = BaseURL + '/profiles/filterblocks'

    payload = {}
    req = requests.get(URL, headers=Auth_Header, params=payload)
    vals = json.loads(req.text)
    print(vals)

'''
Search Profiles

GET /profiles
Parameters:
(All Optional)

customerId integer($int64) Customer ID
name string Profile name
sortColumn string Sort by column (name, customerName)
sortOrder string Sorting order (asc, desc)
pageSize integer($int32) Number of results per page
page integer($int32)

JSON response:

'''

def search_profiles(name):
    URL = BaseURL + '/profiles'
    payload = { 'name': name }
    req = requests.get(URL, headers=Auth_Header, params=payload)
    vals = json.loads(req.text)
    profile_schema = vals['items'][0]
    return profile_schema

'''

Update and existing profile given a profileID and a new structure

'''

def put_profile(pid, data_struct):
    URL = BaseURL + '/profiles/' + str(pid)
    req = requests.put(URL, headers=Auth_Header, json=data_struct)
    if not req.ok:
        print('URL: ', req.url)
        print('Status Code: ', req.status_code)
        print('Reason: ', req.reason)
        print('Orig Request: ')
        print('Body: ', req.request.body)
        print('Request Text: ')
        pprint(req.text)
        return
    return json.loads(req.text)

'''

Add a URL to a Profile, referenced by Profile ID

'''

def add_url(pid, url):
    orig = get_profile_by_id(pid)
    temp = new = orig
    new_url = {'node': url, 'type': 'naked-host-path'}
    blacklist = temp['data']['urlFilter']['blackList']
    blocklist = temp['data']['urlFilter']['blockList']
    changed = False
    if new_url not in blacklist:
        temp['data']['urlFilter']['blackList'].append(new_url)
        changed = True
    if new_url not in blocklist:
        temp['data']['urlFilter']['blockList'].append(new_url)
        changed = True
    if changed:
        new = put_profile(pid, temp)
    return new

'''

Profile black/block list structures

            'blackList': [
                {'node': '34as5rd6tfyg.cabanova.com', 'type': 'naked-host-path'},
                {'node': '3ccacb54.sibforms.com', 'type': 'naked-host-path'},
                {'node': '596808a16dec4fc39413bf34b0a70240.apm.eu-west-1.aws.cloud.es.io', 'type': 'naked-host-path'},
                {'node': 'hmeont.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'ont6933054.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'ovg.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'xert543yuwwer000245.site', 'type': 'naked-host-path'}


'''

def del_url(pid, url):
    orig = get_profile_by_id(pid)
    staged = orig
    blacklist = staged['data']['urlFilter']['blackList']
    blocklist = staged['data']['urlFilter']['blockList']
    target = {'node': url, 'type': 'naked-host-path'}
    while target in blacklist:
        staged['data']['urlFilter']['blackList'].remove(target)
    while target in blocklist:
        staged['data']['urlFilter']['blockList'].remove(target)
    new = put_profile(pid, staged)
    return new

'''
Get Profile by Profile ID

PATH + /{Id}
GET -> params -> {}

JSON response:

{
    'id': 14739,
    'name': 'dns1-profile',
    'customerId': 171,
    'customerName': 'university of toronto',
    'data': {
        'temporarilyDisabled': False,
        'internetSecurity': {
            'safeSearchServices': {
                'BING': False,
                'GOOGLE': False,
                'YOUTUBE': False
            },
            'enableMalwareProtection': True
        },
        'webFilterLevel': {
            'level': 'none',
            'blockList': []
        },
        'internetOffSchedule': {
            'enabled': False,
            'schedules': []
        },
        'contentRestriction': {
            'enabled': False,
            'schedules': [],
            'blockList': []
        },
        'urlFilter': {
            'allowList': [],
            'blockList': [
                {'node': '34as5rd6tfyg.cabanova.com', 'type': 'naked-host-path' },
                {'node': '3ccacb54.sibforms.com', 'type': 'naked-host-path'},
                {'node': '596808a16dec4fc39413bf34b0a70240.apm.eu-west-1.aws.cloud.es.io', 'type': 'naked-host-path'}, {'node': 'hmeont.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'ont6933054.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'ovg.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'xert543yuwwer000245.site', 'type': 'naked-host-path'}
            ],
            'whiteList': [],
            'blackList': [
                {'node': '34as5rd6tfyg.cabanova.com', 'type': 'naked-host-path'},
                {'node': '3ccacb54.sibforms.com', 'type': 'naked-host-path'},
                {'node': '596808a16dec4fc39413bf34b0a70240.apm.eu-west-1.aws.cloud.es.io', 'type': 'naked-host-path'},
                {'node': 'hmeont.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'ont6933054.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'ovg.cabanova.com', 'type': 'naked-host-path'},
                {'node': 'xert543yuwwer000245.site', 'type': 'naked-host-path'}
                ]
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
    URL = BaseURL + '/profiles/' + str(pid)
    payload = {}
    req = requests.get(URL, headers=Auth_Header, params=payload)
    vals = json.loads(req.text)
    if Debug:
        pprint(vals)
    return vals


'''
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

    {
    'id': 9855,
    'name': 'dns4',
    'subscriberId': 'dns4-d7ea98b9-2a59-4265-a5e5-d278e5292cef',
    'timeZone': 'America/Toronto',
    'customerId': 171,
    'ipAddresses': [
        {'id': 22507,
        'address': '128.100.56.135',
        'type': 'V4',
        'networkId': 9855,
        'dynamicSourceAddressId': None,
        'childIPV4': None, 'childIPV6': None,
        'lastChecked': None}],
    'customerName': 'university of toronto',
    'profileId': 14649,
    'profileName': 'dns4-profile',
    'blockPageId': 173,
    'blockPageName': 'utoronto_blockpage-155',
    'reportEmails': None,
    'reportFrequency': 'NEVER'
    },


    {
    'id': 8907,
    'name': 'dns8',
    'subscriberId': 'dns8-abff435d-27f6-47ca-93e7-1609ab156a3c',
    'timeZone': 'America/Toronto',
    'customerId': 171,
    'ipAddresses':
        [{'id': 20396, 'address': '128.100.102.202', 'type': 'V4', 'networkId':
        8907, 'dynamicSourceAddressId': None, 'childIPV4': None, 'childIPV6':
        None, 'lastChecked': None}],
    'customerName': 'university of toronto',
    'profileId': 13179, 'profileName': 'dns8-profile',
    'blockPageId': 173, 'blockPageName': 'utoronto_blockpage-155', 'reportEmails': None,
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


def get_networks(network_id=None, customer_id=None, net_name=None):
    URL = BaseURL + '/networks'

    payload = {}

    if network_id:
        URL += '/' + str(network_id)
        payload['id'] = network_id

    if net_name:
        payload['name'] = str(net_name)

    print(payload)
    req = requests.get(URL, headers=Auth_Header, params=payload)
    vals = json.loads(req.text)
    print(vals)

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
    URL = BaseURL + '/networks/timezones'

    req = requests.get(URL, headers=Auth_Header)
    vals = json.loads(req.text)
    print(vals)

'''
Provisioning Events

JSON representation of an Event:

{
    "id": 68,
    "entityType": "ZONE",
    "operation": "CREATE",
    "status": "SUCCESS",
    "customername": "CIRA",
    "userName": "cira_full_access",
    "dateCreated": 1425922462487,
    "lastUpdated": 1425922468970,
    "steps": [ ...... ],
    "targetEntityName": "april14test.ca.",
    "targetEntityCustomerName": "CIRA"
}

Field Definitions:

id: The internal identifier used to identify a provisioning event.
    Generated by system when provisioning operation performed.

entityType: The D-Zone Entity Type which the provisioning operation
            was applied to.  It is one of:
            "ZONE", "MASTER_NAME_ SERVER" and "SIGNATURE".

operation: The operation performed by this event is one of:
            "CREATE", "UPDATE" and "DELETE".

status: The latest status of the event and it is one of "PENDING",
"IN_PROCESS", "SUCCESS" and "FAILED".

customerName: The name of the customer who performed the operation.

username: The username of the user who performed the operation

dateCreated: The timestamp when the operation performed
             in format of date format is: dd/MM/yyyy HH:mm:ss

lastUpdated: The timestamp when the operation event last updated
             in format of date format is dd/MM/yyyy HH:mm:ss

steps: A list of provisioning EventSteps associated with the operation

targetEntityName: The name of entity which the provisioning operation
                  was applied to.

targetEntityCustomerName: The customer which the target entity belongs to.


EventStep Object:
{
    "id": 2035,
    "description": "provisioning uncompleted",
    "dateCreated": 1427901124418
}

Field Descriptions:

id: The internal identifier used to identify a provisioning event step.
    Generated by system when provisioning oper- ation step executed.

description: A brief summery describing the event step including
             the request parameters.

dateCreated: The timestamp when the event step executed.


ProvisioningEvent Search Result:

{
    "hasNext": false,
    "hasPrevious": false,
    "page": 0,
    "items": [ ........],
    "totalRowCount": 7,
    "totalPageCount": 1,
    "currentRowCount": 7
}

Field Descriptions:

    hasNext: Boolean if there are more pages of results
    hasPrevious: Boolean if there were more pages before results
    Page: the Number of the page returned
    totalPageCount: Total number of pages for the entire result
    currentRowCount: Numberof items returned by the search
    items: the list of dictionary items returned

Functions:

GET:

api.d-zone.ca/provisioningevents?
params:
entityType=&entityId=&operation=&status=&username=&startDate=&endDate=
&targetEntityName=&page=&pageSize

Endpoint used to search D-Zone provisioning events generated by
the users customer during D-Zone provisioning operation.
Returns the provisioning event search results.


Query Parameters:

entityType: The D-Zone entity type on which the operations were applied to.
            It is one of "zones", "masters" and "signatures".
entityId: The id of the entity on which the operations were applied to.
           If it is specified the entityType has to be specified as well.
targetEntityName: The entity name which the provisioning operations
                  were applied to.
operation: The provisioning operation performed.
           It is one of "ceate", "update" and "delete".
status: The latest provisioning status being searched.
        It is one of "pending", "in_process", "success" and "failed"
username: The D-Zone user who performed the operation.
          The search on username is partially text search.
startDate: The earliest date and time in the time range of
           the operation performed (inclusive).
           It has to be in URL encoded date and time format.
For example: 31/03/2015 12:20:30 willbe 31%2F03%2F2015+12%3A20%3A30.
endDate: The latest date and time in the time range
         of the operation performed (exclusive).
         It has to be in URL encoded date and time format.
For example: 31/03/2015 12:20:30 will be: 31%2F03%2F2015+12%3A20%3A30

'''

def test_functions():

    dnsfirewall_init()
#    prof = add_url(14739, 'www.quist.ca')
#    print('after add')
#    pprint(prof)
    print('before')
    prof = get_profile_by_id(14739)
    pprint(prof)
#   prof = add_url(14739, 'www.quist.ca')
    prof = del_url(14739, 'www.quist.ca')
    print('after')
    pprint(prof)
    exit()
# working
    get_account_info()
    get_timezones()
    get_networks(net_name='dns8')
    get_threatfeeds()
    domainlookup('cira.ca')
    get_blockpages()
    get_profiles_filterblocks()
    search_profiles('dns1')
    get_profile_by_id(14739)
#    prof = del_url(14739, 'www.quist.ca')
# still broken

    vals = get_zoneowners()
    pprint(vals)
    print

    zone_id = name2id_zone(zone)
    print(zone, zone_id)

    vals = get_zone_info(zone_id)
    pprint(vals)
    print

    sys.exit()

    vals = create_zone(zone, ['ans1', 'ans2'])
    pprint(vals)
    print

    vals = delete_zone(zone)
    pprint(vals)
    print

    sys.exit()

# vals = get_zones()
# pprint(vals[1:10])
    zone_id = 427
    zone = 'test.uoft.ca'
    vals = get_zone_info(zone_id)
    pprint(vals)

    print('Zone ID:', zone_id, 'Zone Name:', id2name_zone(zone_id))

    print('Zone Name:', zone, 'Zone ID:', name2id_zone(zone))

    vals = get_servicetypes()
    pprint(vals)

    vals = get_servicetype_info(2)
    pprint(vals)

    zone = 'gtanet.ca.'
    zone = 'test.utoronto.ca.'

    vals = get_zone_info(zone)
    pprint(vals)

    print('get_zones:')
    vals = get_zones()
    pprint(vals[0:10])

    vals = get_provisioning_events()
    pprint(vals)

    vals = get_algorithms()
    pprint(vals)

    val = get_masters()
    pprint(val)
    print

    vals = get_master_ids()
    pprint(vals)
    print

    for i in master_ids:
        print(id2name_master(i))
        vals = get_master_info(i)
        pprint(vals)
    print

    val = get_master_info(1656)
    pprint(val)

    id = 764
    val = id2name_zoneowner(id)
    print(id, val)

    name = 'russ'
    val = name2id_zoneowner(name)
    print(name, val)

    name = 'uoft'
    val = name2id_zoneowner(name)
    print(name, val)

    vals = create_zoneowner('russ')
    pprint(vals)
    print

    vals = get_zoneowners('')
    pprint(vals)
    print

    vals = get_zoneowners('uoft')
    pprint(vals)
    print

    vals = get_zoneowner(name2id_zoneowner('russ'))
    pprint(vals)
    print

    vals = create_zoneowner('bozo')
    pprint(vals)
    print

    vals = get_zoneowners('')
    pprint(vals)
    print

    owner_obj = {
        'name': 'ralph',
        'id': name2id_zoneowner('bozo'),
    }

    vals = update_zoneowner(owner_obj)
    pprint(vals)
    print

    vals = get_zoneowners('')
    pprint(vals)
    print

    vals = delete_zoneowner(name2id_zoneowner('ralph'))
    pprint(vals)
    print

    vals = get_zoneowners('')
    pprint(vals)
    print

    print('get_algorithms:')
    algs = get_algorithms()
    pprint(algs)

    print('get_provisioning_events')
    get_provisioning_events()
    print

    print('get_masters:')
    masters = get_masters()
    pprint(masters)
    print

    sys.exit()

    print('get_zoneowners:')
    zoneowners = get_zoneowners()
    pprint(zoneowners)
    print

    print('get_zoneowner')
    zoneowner = get_zoneowner(764)
    pprint(zoneowner)
    print

    print('get_servicetypes:')
    vals = get_servicetypes()
    pprint(vals)
    print

    id = get_servicetype_id()
    print('get_servicetype_id: ', id)
    print

    print('get_servicetype_info for:', id)
    vals = get_servicetype_info(id)
    pprint(vals)
    print

#    print('delete zone')
#    vals = delete_zone(zone)
#    pprint(vals)

#    print('create zone:', zone)
#    vals = create_zone(zone)
#    print(vals)


def main():
    test_functions()
    sys.exit()


if __name__ == "__main__":
    main()
