#!/usr/bin/env python

import os
import sys
import logging
from pprint import pprint

from cira_am import config
from cira_am import api

Logger = logging.getLogger(__name__)
Logger.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.INFO)
config.Logger = Logger

'''Higher Level Utility CIRA DNS Firewall Functions'''

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
    fn = 'dnsfirewall_init'

    creds = {
        'username': os.environ['CLIENT_UID'],
        'password': os.environ['CLIENT_PW'],
        'client_id': os.environ['CLIENT_ID'],
        'client_secret': os.environ['SECRET_KEY'],
        'grant_type': 'password'
    }
    
    tokens = api.fetch_tokens(creds)
    config.AuthHeader['Authorization'] = tokens['token_type'] + ' ' + tokens['access_token']
    config.GetAuthHeader['Authorization'] = tokens['token_type'] + ' ' + tokens['access_token']
    config.CustomerName = creds['client_id']
    
    if config.Debug:
        Logger.debug('{}: Authorization Header: {}'.format(fn, config.AuthHeader))

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

def profile_name_to_id(name):
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

def pretty_print(profile):
    name = profile['name']
    pid = profile['id']
    print('Profile:')
    print('    Name: {}'.format(name))
    print('    Id: {}'.format(pid))
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
    api.get_networks(net_name='dns8')
    api.get_threatfeeds()
    api.domainlookup('cira.ca')
    api.get_blockpages()
    api.get_profiles_filterblocks()
    api.search_profiles('dns1')
    api.get_profile_by_id(14739)


def main():
    test_functions()
    sys.exit()
