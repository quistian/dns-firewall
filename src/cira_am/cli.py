#!/usr/bin/env python

import click
import re

from click import group, pass_context, option, argument, command, echo
from click import Context
from pprint import pprint

from cira_am import util, api, config
from cira_am import config

def validate_fqdn(ctx, param, value):
    if value == 'rights':
        return validate_value(ctx, param, value)
    else:
        pattern = '[\w]+(\.[\w]+)+'
        if not re.match(pattern, value):
            raise click.BadParameter('Value must be in the form: a.b.c.d')
        return value

def validate_value(ctx, param, value):
    return value

@group()
@option(
    '-v', '--verbose', '--debug', 'verbose',
    is_flag=True,
    help='Show what is going on for debugging purposes'
)
@option(
    '-s', '--silent',
    is_flag=True,
    help='Minimize the output from commands. Silence is golden'
)
@pass_context

def run(ctx: Context, silent, verbose):
    ctx.obj = dict()
    ctx.obj['SILENT'] = silent
    ctx.obj['DEBUG'] = verbose
    config.Silent = silent
    config.Debug = verbose
    util.dnsfirewall_init()
  
# Define common options to share between subcommands
fqdn = argument(
    'fqdn',
    type=click.STRING,
    default='bozo.the.clown.ca',
    callback=validate_fqdn
)
pname = argument(
    'pname',
    type=click.STRING,
    callback=validate_value,
)
nname = argument(
    'nname',
    type=click.STRING,
    callback=validate_value,
)
name = argument(
    'name',
    type=click.STRING,
    callback=validate_value,
)
number = argument(
    'number',
    type=click.INT,
    default=0,
    callback=validate_value
)

# Profiles Group of commands

@run.group('profile')
def profile():
    pass

@profile.command()
@pass_context
@option( '--by-id', 'byid',  help='view a profile by ID number')
@option( '--by-name', 'byname', help='view by matching name')
@option( '--all', 'awl', is_flag=True, help='View/List all the profiles')
def view(ctx, byid, byname, awl): 
    if awl:
        profs = api.search_profiles('')
        for prof in profs['items']:
            util.profile_pretty_print(prof)
    elif byid:
        prof = api.get_profile_by_id(byid)
        util.profile_pretty_print(prof)
    elif byname:
        if config.Debug:
            click.echo(' searching for profiles contaning {}\n'.format(byname))
        profs = api.search_profiles(byname)
        for prof in profs['items']:
            util.profile_pretty_print(prof)

@profile.command()
@pass_context
@option( '--add', 'add', type=(str, str), help='Add a fqdn to an existing profile blocklist')
@option( '--del', '--delete', 'delete', type=(str, str), help='Remove a fqdn from an existing profile blocklist')
def url(ctx, add, delete):
    if add:
        (fqdn, profile) = add
        if ctx.obj['DEBUG']:
            click.echo(' adding fqdn: {} to profile: {}\n'.format(fqdn, profile))
        util.add_url(fqdn, profile)
    elif delete:
        (fqdn, profile) = delete
        if ctx.obj['DEBUG']:
            click.echo(' removing fqdn: {} from profile: {}\n'.format(fqdn, profile))
        util.del_url(fqdn, profile)

@profile.command()
@pass_context
@pname
def create(pname):
    util.profile_create(add)

@profile.command()
@pass_context
@pname
def delete(pname):
    util.profile_delete(delete)

@profile.command()
@pass_context
@pname
def name2id(pname):
    if config.Debug:
        click.echo(' searching for profile id for name {}\n'.format(name2id))
    ids = util.profile_name_to_ids(pname)
    l = len(ids)
    click.echo('Profile Ids whose Profile names match {}:  {}'.format(name2id, ids))

# @option( '-D', '--del-by-id', 'delid', help='Delete an existing profile given ID number')

@run.group('network')
def network():
    pass

@network.command()
@pass_context
@option( '--by-id', 'byid',  help='view a network by ID number')
@option( '--by-name', 'byname', help='view by matching name')
@option( '--all', 'awl', is_flag=True, help='View/List all the networks')
def view(ctx, byid, byname, awl): 
    if awl:
        util.networks_search('')
    elif byname:
        if ctx.obj['DEBUG']:
            click.echo(' getting networks information matching {}'.format(search))
        util.networks_search(byname)
    elif byid:
        util.networks_get_by_id(byid)

@network.command()
@nname
@pass_context
def create(ctx, nname):
        newnet = util.network_create(nname)
        if ctx.obj['DEBUG']:
            pprint(newnet)

@network.command()
@nname
@pass_context
def delete(ctx, nname):
    val = util.network_delete(nname)
    if ctx.obj['DEBUG']:
        print(val)

@network.command()
@option( '--add', 'addip', type=(str, str), help='Add a CIDR block to a network by name')
@option( '--del', 'delip', type=(str, str), help='Remove a CIDR from a network by name')
@pass_context
def cidr(ctx, addip, delip):
    if addip:
        (cidr, netname) = addip
        if ctx.obj['DEBUG']:
            click.echo(' adding cidr: {} to network: {}'.format(cidr, netname))
        util.networks_add_cidr(cidr, netname)
    elif delip:
        (cidr, netname) = delip
        if ctx.obj['DEBUG']:
            click.echo(' removing cidr: {} to network: {}'.format(cidr, netname))
        util.networks_del_cidr(cidr, netname)

@network.command()
@nname
@pass_context
def name2id(ctx, nname):
    netids = util.network_name_to_ids(nname)
    if len(netids):
        print(netids)
    else:
        print('No network names match: {}'.format(nname))

# @option( '-D', '--del-by-id', 'delid', help='Delete an network given ID number')

@run.command()
@pass_context
@name
def customers(ctx, name):
    if ctx.obj['DEBUG']:
        click.echo(' getting customer: {} information\n'.format(name))
#    api.get_customer_by_id(name)
    api.search_customers(name)

@run.command()
@pass_context
def null(ctx):
    if ctx.obj['DEBUG']:
        click.echo(' Should just run the dnsfirewall_init function')
    
if __name__ == '__run__':
    run()
