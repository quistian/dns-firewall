# dns-firewall

This project allows remote access and editing of a personal or institutional account
on the CIRA DNS-Firewall

## Getting Started

To get started, download the source code from Github:

```bash
$ git clone https://github.com/quistian/dns-firewall
```

Set up a Python3 virtual environment for dns-firewall to run in:

```bash
$ cd dns-firewall
$ python3 -m venv `pwd`/venv
$ . venv/bin/activate
(venv) $ pip install --upgrade pip
(venv) $ pip install --editable .
```

Customize your Unix shell (this documentation assumes /bin/sh, /bin/bash or /bin/zsh) environment to set the BAM URL, Username and Password.

```bash
(venv) $ cat example-env
export CLIENT_UID='bozo_the_clown'
export CLIENT_PW='leeXahQu8gufoosh'
export CLIENT_ID='cirque de soleil'
export SECRET_KEY='kW&Iz|<[/DAp6Z-d2F`8ShX0`DHe5%rHY&}<Y%rJ]7f*v/v0Of,f7%MB^+'

(venv) $ cp example-venv ~/.dns-firewall-env
(venv) $ vi ~/.dns-firewall-env
(venv) $ . ~/.dns-firewallbamrc
```

The CIRA DNS Firewall interface will not work with out these SHELL variables being set
These are the credentials needed by the Firewall Rest API
