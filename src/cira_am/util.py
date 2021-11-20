#!/usr/bin/env python

import json
import logging
import os
import sys
import time

from pprint import pprint
from dotenv import load_dotenv

from cira_am import config
from cira_am import api

Logger = logging.getLogger(__name__)
Logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.INFO)
config.Logger = Logger

# DNS Firewall object schemas

# Networks object schema

'''

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
    ...
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


'''
Profile schema:

profile_template = {
    'customerId': 171,
    'customerName': 'university of toronto',
    'data': {
        'contentRestriction': {'blockList': [], 'enabled': False, 'schedules': []},
        'internetOffSchedule': {'enabled': False, 'schedules': []},
        'internetSecurity': {
            'enableMalwareProtection': True,
            'safeSearchServices': {'BING': False, 'GOOGLE': False, 'YOUTUBE': False}
        },
        'temporarilyDisabled': False,
        'urlFilter': {'allowList': [], 'blackList': [], 'blockList': [], 'whiteList': []},
        'webFilterLevel': {'blockList': [], 'level': 'none'}
    },
    'feedSubscriptions': [
        {'active': True, 'threatFeedName': 'CCCS'},
        {'active': True, 'threatFeedName': 'Cybertip'},
        {'active': True, 'threatFeedName': 'CanSSOC'}
    ],
    'id': 15236,
    'name': 'template-profile',
    'networkIdNames': {'10213': 'template'}
}

network_template = {
    'id': 10213,
    'name': 'template',
    'subscriberId': 'template-0347da10-ded1-4e76-a91a-0ae33ffcb035',
    'timeZone': 'America/Toronto',
    'customerId': 171,
    'ipAddresses': [
        {
        'id': 23206,
        'address': '128.100.0.0/24',
        'type': 'V4',
        'networkId': 10213,
        'dynamicSourceAddressId': None,
        'childIPV4': None,
        'childIPV6': None,
        'lastChecked': None
        }
    ],
    'customerName': 'university of toronto',
    'profileId': 15236,
    'profileName': 'template-profile',
    'blockPageId': 173,
    'blockPageName': 'utoronto_blockpage-155',
    'reportEmails': [],
    'reportFrequency': 'NEVER'
}

'''

# Higher Level Utility CIRA DNS Firewall Functions

'''
fetch_tokens response

 {
 "access_token": "jaktyTS1QcjMtV0JrS2l4bzZ3bFpmV2pVUXhGUHB6OFNjIODM3NzgsImlhdCI ... "
 "expires_in": 300,
 "refresh_expires_in": 1800,
 "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4YWQ0Zjgw ... ",
 "token_type": "Bearer",
 "not-before-policy": 0,
 "session_state": "0e82a3e6-1160-42c5-b7d0-8271e32782e3",
 "scope": "Customer_API_Client_Template"
 }
'''

def dnsfirewall_init():
    fn = 'util.dnsfirewall_init'
    tokf = os.environ['HOME'] + '/.dns-firewall-tokens.json'

    load_dotenv()
    creds = {
        'username': os.environ['CLIENT_UID'],
        'password': os.environ['CLIENT_PW'],
        'client_id': os.environ['CLIENT_ID'],
        'client_secret': os.environ['SECRET_KEY'],
        'grant_type': 'password'
    }

    if os.path.exists(tokf):
        with open(tokf, 'r') as inf:
            ftokens = json.load(inf)
        token_life = ftokens['expires_in']
        refresh_life = ftokens['refresh_expires_in']
        age = int(time.time() - os.path.getmtime(tokf))
        if age > refresh_life:
            if config.Debug:
                print('fn: {} tokens age {} secs, too old for refresh, getting new tokens'.format(fn, age))
            tokens = api.fetch_fresh_tokens(creds)
            config.AuthHeader['Authorization'] = tokens['token_type'] + ' ' + tokens['access_token']
            with open(tokf, 'w') as outf:
                outf.write(json.dumps(tokens, indent=4))
        elif age < token_life:
            if config.Debug:
                print('fn: {} access token age: {} secs, fetching from file: {}'.format(fn, age, tokf))
            config.AuthHeader['Authorization'] = ftokens['token_type'] + ' ' + ftokens['access_token']
        else:
            if config.Debug:
                print('fn: {} access token, age: {} secs,  has expired, being refreshed from {}'.format(fn, age, tokf))
            refresh_creds = {
                    'client_id': creds['client_id'],
                    'client_secret': creds['client_secret'],
                    'grant_type': 'refresh_token',
                    'refresh_token': ftokens['refresh_token']
            }
            tokens = api.fetch_refresh_tokens(refresh_creds)
            config.AuthHeader['Authorization'] = tokens['token_type'] + ' ' + tokens['access_token']
            with open(tokf, 'w') as outf:
                outf.write(json.dumps(tokens, indent=4))
    else:
        tokens = api.fetch_fresh_tokens(creds)
        config.AuthHeader['Authorization'] = tokens['token_type'] + ' ' + tokens['access_token']
        with open(tokf, 'w') as outf:
            outf.write(json.dumps(tokens, indent=4))

#        Logger.debug('{}: Authorization Header: {}'.format(fn, config.AuthHeader))
#   config.CustomerName = creds['client_id']


'''
Add a URL to a Profile, blacklist and blocklist referenced by Profile Name
'''

def add_url(url, name):
    profs = api.search_profiles(name)
    items = profs['items']
    l = len(items)
    if l == 1:
# search_profiles data has domain override off and omits feedSubscriptions
# hence the call to get_profile_by_id
        pid = items[0]['id']
        item = api.get_profile_by_id(pid)
        pname = item['name']
        node = {'node': url, 'type': 'naked-host-path'}
        if node not in item['data']['urlFilter']['blackList']:
            item['data']['urlFilter']['blackList'].append(node)
            item['data']['urlFilter']['blockList'].append(node)
            new = api.put_profile(pid, item)
            print('Added {} to {}'.format(url, pname))
        else:
            print('{} blocklst already contains {}'.format(pname,url))
    elif l == 0:
        print('There were no profile names matching: {}'.format(prof_name))
    else:
        print('There were more than 1 profile names which  matched: {}'.format(prof_name))
    
'''
Remove a URL from a Profile, blacklist and blocklist referenced by Profile Name
'''

def del_url(url, name):
    profs = api.search_profiles(name)
    items = profs['items']
    l = len(items)
    if l == 1:
# search_profiles data has domain override off and omits feedSubscriptions
# hence the call to get_profile_by_id
        pid = items[0]['id']
        item = api.get_profile_by_id(pid)
        pname = item['name']
        node = {'node': url, 'type': 'naked-host-path'}
        if node not in item['data']['urlFilter']['blackList']:
            print('{} blocklst does not contain {}'.format(pname,url))
        else:
            while node in item['data']['urlFilter']['blackList']:
                item['data']['urlFilter']['blackList'].remove(node)
            while node in item['data']['urlFilter']['blockList']:
                item['data']['urlFilter']['blockList'].remove(node)
            new = api.put_profile(pid, item)
            print('Deleted {} from {} blocklist'.format(url, pname))
    elif l == 0:
        print('There were no profile names matching: {}'.format(prof_name))
    else:
        print('There were more than 1 profile names which  matched: {}'.format(prof_name))
    
'''
Add a URL to a Profile, blacklist and blocklist referenced by Profile ID
'''

def add_url_by_pid(url, pid):
    orig = api.get_profile_by_id(pid)
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
        new = api.put_profile(pid, temp)
        return new
    else:
        return None

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

def del_url_by_pid(url, pid):
    orig = api.get_profile_by_id(pid)
    staged = orig
    blacklist = staged['data']['urlFilter']['blackList']
    blocklist = staged['data']['urlFilter']['blockList']
    target = {'node': url, 'type': 'naked-host-path'}
    while target in blacklist:
        staged['data']['urlFilter']['blackList'].remove(target)
    while target in blocklist:
        staged['data']['urlFilter']['blockList'].remove(target)
    new = api.put_profile(pid, staged)
    return new

def profile_name_to_ids(name):
    prof = api.search_profiles(name)
    items = prof['items']
    pids = []
    for item in items:
        pids.append(item['id'])
    return pids

def profile_exists(pid):
    prof = api.get_profile_by_id(pid)
    if prof:
        return True
    else:
        return False
'''

A profile can be created with no networks associated.

'''

def profile_create(pname):
    toks = pname.split('-')
    if toks[-1] != 'profile':
        cname = pname + '-profile'
    else:
        cname = pname
    ids = profile_name_to_ids(cname)
    if len(ids):
        print('Profile {} already exists'.format(cname))
        prof = api.get_profile_by_id(ids[0])
    else:
        ids = profile_name_to_ids('template-profile')
        prof = api.get_profile_by_id(ids[0])
        prof['name'] = cname
        prof['id'] = '0'
        prof['networkIdNames'] =  {}
        new = api.create_profile(prof)
        if config.Debug:
            pprint(new)
        prof = new
    return prof

'''

A profile can not be deleted before it has all networks removed

'''

def profile_delete(pname):
    toks = pname.split('-')
    if toks[-1] != 'profile':
        cname = pname + '-profile'
    else:
        cname = pname
    pids = profile_name_to_ids(cname)
    l = len(pids)
    if l == 1:
        pid = pids[0]
        prof = api.get_profile_by_id(pid)
        netids = prof['networkIdNames']
        if len(netids):
            for k in netids:
                netname = netids[k]
                netid = k
            print('Cannot delete profile: {} as it still contains:'.format(cname))
            net = api.get_network_by_id(netid)
            network_pretty_print(net)
        else:
            api.delete_profile(pid)
    else:
        print('Profile {} does not exist'.format(cname))

'''
Search for all networks matching a string
'''

def networks_search(search_str):
    fn = 'util.networks_search'
    vals = api.search_networks(name=search_str)
    for net in vals['items']:
        network_pretty_print(net)

def networks_get_by_id(netid):
    fn = 'util.networks_get_by_id'
    vals = api.get_network_by_id(netid)
    if vals:
        network_pretty_print(vals)
    else:
        print('No network matching Id: {}'.format(netid))

def network_name_to_ids(netname):
    fn = 'util.network_name_to_ids'
    vals = api.search_networks(netname)
    nets = vals['items']
    netpids = []
    for net in nets:
        netpids.append(net['id'])
    return netpids

def networks_add_cidr(cidr, netname):
    nets = api.search_networks(name=netname)
    items = nets['items']
    l = len(items)
    if l == 1:
        netid = items[0]['id']
        item = api.get_network_by_id(netid)
        netname = item['name']
        net = {
            'id': 0,
            'address': cidr,
            'type': 'V4',
            'networkId': netid,
            'dynamicSourceAddressId': None,
            'childIPV4': None,
            'childIPV6': None,
            'lastChecked': None
        }
        if net not in item['ipAddresses']:
            item['ipAddresses'].append(net)
            new = api.put_network(netid, item)
            print('Added address {} to network {}'.format(cidr, netname))
        else:
            print('network {} already contains {}'.format(netname,cidr))
    elif l == 0:
        print('There were no network names matching: {}'.format(netname))
    else:
        print('There were more than 1 network names which matched: {}'.format(netname))
    return new

def networks_del_cidr(cidr, netname):
    nets = api.search_networks(netname)
    items = nets['items']
    l = len(items)
    if l == 1:
        netid = items[0]['id']
# this is perhaps not needed if inital search yields the same data
        item = api.get_network_by_id(netid)
        nname = item['name']
        ipaddrs = item['ipAddresses']
        changed = False
        for ipaddr in ipaddrs:
            if ipaddr['address'] == cidr:
                changed = True
                item['ipAddresses'].remove(ipaddr)
        if changed:
            print('Deleted {} from network {}'.format(cidr, netname))
            new = api.put_network(netid, item)
        else:
            print('Address {} is not part of network {}'.format(cidr, netname))
    elif l == 0:
        print('There were no networks names matching: {}'.format(netname))
    else:
        print('There were more than 1 networks  which matched: {}'.format(netname))
    

'''
The required fields are:
    name
    timezone
    network/ipaddr

Optional:
    block_page

Creating a new network will create a profile of the same name

'''

Network_Template = {
    'id': 0,
    'name': 'temp',
    'timeZone': 'America/Toronto',
    'ipAddresses': [
         {
            'address': '128.0.{}.{}'.format(*__import__('random').sample(range(0,255),2)),
            'childIPV4': None,
            'childIPV6': None,
            'dynamicSourceAddressId': None,
            'id': 23206,
            'lastChecked': None,
            'networkId': 10213,
            'type': 'V4',
        }
    ],
    'profileId': 0,
    'blockPageId': 173,
    'blockPageName': 'utoronto_blockpage-155',
    'reportEmails': [ ],
    'reportFrequency': 'NEVER',
}

'''

Networks can not be created in isolation.
They need to be associated with a profile

'''

def network_create(netname):
    ids = network_name_to_ids(netname)
    l = len(ids)
    if l == 1:
        print('Network {} already exists'.format(netname))
        net = api.get_network_by_id(ids[0])
    elif l == 0:
        tempnet = Network_Template
        tempnet['name'] = netname
        tempnet['networkIdNames'] =  {}
        new = api.create_network(tempnet)
        if config.Debug:
            pprint(new)
        net = new
    return net

def network_delete(netname):
    ids = network_name_to_ids(netname)
    l = len(ids)
    if l == 1:
        val = api.delete_network(ids[0])
    elif l == 0:
        print('Network {} does not exist'.format(netname))
    return val
    
def network_pretty_print(net):
    fn = 'util.network_pretty_print'
    name = net['name']
    nid = net['id']
    profile = net['profileName']
    blockpage = net['blockPageName']
    print('Network:')
    print('    Name: {}'.format(name))
    print('    Id: {}'.format(nid))
    print('    Associated Profile: {}'.format(profile))
    print('    Associated BlockPage: {}'.format(blockpage))
    print('    Addresses:')
    for addr in net['ipAddresses']:
        print('        address {}'.format(addr['address']))
        print('        addressId {}'.format(addr['id']))

def profile_pretty_print(profile):
    name = profile['name']
    pid = profile['id']
    networks = profile['networkIdNames']
    print('Profile:')
    print('    Name: {}'.format(name))
    print('    Id: {}'.format(pid))
    print('    Networks: {}'.format(networks))
    print('    Block List:')
    blist = profile['data']['urlFilter']['blackList']
    for node in blist:
        print('        {}'.format(node['node']))

def test_functions():

    dnsfirewall_init()
    prof = api.get_profile_by_id(14739)
    pprint(prof)
    prof = del_url(14739, 'www.quist.ca')
    print('after')
    pprint(prof)
    exit()
# working
    api.get_account_info()
    api.get_timezones()
    api.get_threatfeeds()
    api.domainlookup('cira.ca')
    api.get_blockpages()
    api.get_profiles_filterblocks()
    api.get_profile_by_id(14739)


def main():
    test_functions()
    sys.exit()
