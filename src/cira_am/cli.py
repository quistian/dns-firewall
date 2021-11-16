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
    
    if verbose:
        click.echo('action: {}'.format(ctx.invoked_subcommand))
    util.dnsfirewall_init()
  
# Define common options to share between subcommands
fqdn = argument(
    'fqdn',
    type=click.STRING,
    default='bozo.the.clown.ca',
    callback=validate_fqdn
)
name = argument(
    'name',
    type=click.STRING,
    default='ns',
    callback=validate_value,
)
profile = argument(
    'profile',
    type=click.STRING,
    default='ns',
    callback=validate_value,
)
number = argument(
    'number',
    type=click.INT,
    default=0,
    callback=validate_value
)


    
@run.command()
@pass_context

@option( '-a', '--create', '--add', 'add',  help='Add a new profile with given name')
@option( '-d', '--del', '--delete', 'delete',  help='Delete an existing profile matching given name')
@option( '-D', '--del-by-id', 'delid', help='Delete an existing profile given ID number')
@option( '-l', '--list', '--view', 'view', is_flag=True, help='View/List all the profiles')
@option( '-s', '--search', help='Search for a profile by substring')
@option( '--view-by-id', 'viewpid',  help='view a profile by ID number')
@option( '--name-to-id', 'name2id',  help='Helper function to find a profile number')
@option( '--add-url', 'addurl', type=(str, str), help='Add a fqdn to an existing profile blocklist')
@option( '--del-url', 'delurl', type=(str, str), help='Remove a fqdn from an existing profile blocklist')

def profiles(ctx, add, delete, delid, view, search, viewpid, name2id, addurl, delurl):
    if add:
        util.profile_create(add)
    elif delete:
        util.profile_delete(delete)
    elif view:
        profs = api.search_profiles('')
        for prof in profs['items']:
            util.pretty_print(prof)
    elif viewpid:
        prof = api.get_profile_by_id(viewpid)
        util.pretty_print(prof)
    elif search:
        if config.Debug:
            click.echo(' searching for profiles contaning {}\n'.format(search))
        profs = api.search_profiles(search)
        for prof in profs['items']:
            util.pretty_print(prof)
    elif name2id:
        if config.Debug:
            click.echo(' searching for profile id for name {}\n'.format(name2id))
        ids = util.profile_name_to_ids(name2id)
        l = len(ids)
        click.echo('Profile Ids whose Profile names match {}:  {}'.format(name2id, ids))
    elif addurl:
        (fqdn, profile) = addurl
        if ctx.obj['DEBUG']:
            click.echo(' adding fqdn: {} to profile: {}\n'.format(fqdn, profile))
        util.add_url(fqdn, profile)
    elif delurl:
        (fqdn, profile) = delurl
        if ctx.obj['DEBUG']:
            click.echo(' removing fqdn: {} from profile: {}\n'.format(fqdn, profile))
        util.del_url(fqdn, profile)

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
