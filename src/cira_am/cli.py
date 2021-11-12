#!/usr/bin/env python

import click

@click.command()
@click.option('--count', default=1, help='Number of revs')
@click.option('--name', prompt='Your name: ',
        help='The person receiving the greeting')

def hello(count, name):
    """ Simple test programme """
    for j in range(count):
        click.echo(f"Hi {name}!")

if __name__ == '__main__':
    hello()
