#!/usr/bin/python

# enumall is a refactor of enumall.sh providing a script to identify subdomains using several techniques and tools.
# Relying heavily on the stellar Recon-NG framework and Alt-DNS, enumall will identify subdomains via search engine
# scraping (yahoo, google, bing, baidu), identify subdomains using common OSINT sites (shodan, netcraft), identify
# concatenated subdomains (altDNS), and brute-forces with a stellar subdomain list (formed from Bitquark's subdomain
# research, Seclists, Knock, Fierce, Recon-NG, and more) located here:
# https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/sorted_knock_dnsrecon_fierce_recon-ng.txt
# 
# Alt-DNS Download: https://github.com/infosec-au/altdns
#
# by @jhaddix and @leifdreizler
# Modified by Th3R0ck

import argparse
import re
import datetime
import time
import os, random
import sys
import math

try:
	from config import *
except:
	reconPath = "/usr/share/recon-ng/"
	altDnsPath = "/opt/altdns/"



sys.path.insert(0,reconPath)
from recon.core import base
from recon.core.framework import Colors

if altDnsPath:
	sys.path.insert(1, altDnsPath)

RESOLVERS_FILE = "/opt/massdns/usresolvers.txt"

def run_module(reconBase, module, domain):
    x = reconBase.do_load(module)
    x.do_set("SOURCE " + domain)
    x.do_run(None)

def load_resolvers(infile):
    resolvers_list = list()
    if os.path.isfile(infile):
        with open(infile) as data:
            for line in data:
                line = line.rstrip()
                resolvers_list.append(line)

    return resolvers_list

def get_random_resolver_ip(resolver_file=RESOLVERS_FILE):
    resolvers_list = load_resolvers(resolver_file)

    return resolvers_list[random.randint(0,len(resolvers_list)-1)]

def run_recon(domains, bruteforce):
    #stamp = datetime.datetime.now().strftime('%M:%H-%m_%d_%Y')
    #wspace = domains[0]+stamp

    wspace = domains[0]

    reconb = base.Recon(base.Mode.CLI)
    reconb.init_workspace(wspace)
    reconb.onecmd("TIMEOUT=100")
    #dns_resolver_ip = get_random_resolver_ip()
    #reconb.options["nameserver"] = dns_resolver_ip
    #reconb.onecmd("NAMESERVER={}".format(dns_resolver_ip))
    module_list = ["recon/domains-hosts/bing_domain_web",
                   "recon/domains-hosts/shodan_hostname",
                   "recon/domains-hosts/google_site_web",
                   "recon/domains-hosts/shodan_hostname",
                   "recon/domains-hosts/certificate_transparency",
                   #"recon/domains-hosts/netcraft",
                   #"recon/domains-hosts/threatcrowd",
                   #"recon/domains-hosts/hackertarget",
                   "recon/domains-hosts/builtwith",
                   "recon/domains-hosts/mx_spf_ip",
                   "recon/netblocks-hosts/shodan_net",
                   "recon/domains-hosts/google_site_api",
                   "recon/netblocks-companies/whois_orgs",
                   "recon/domains-vulnerabilities/punkspider",
                   "recon/domains-vulnerabilities/xssed",
                   "recon/domains-vulnerabilities/xssposed",
                   "recon/domains-vulnerabilities/ghdb",
                   "recon/hosts-hosts/reverse_resolve",
                   "recon/repositories-vulnerabilities/gists_search",
                   "recon/companies-multi/github_miner",
                   "recon/hosts-hosts/resolve"

                   ]

    for domain in domains:
        for module in module_list:
            print("Attempting Module {}".format(module))
            run_module(reconb, module, domain)

        #subdomain bruteforcing
        x = reconb.do_load("recon/domains-hosts/brute_hosts")
        if bruteforce:
            x.do_set("WORDLIST " + bruteforce)
        else:
            x.do_set("WORDLIST /usr/share/recon-ng/data/hostnames.txt")
            x.do_set("SOURCE " + domain)
            x.do_run(None)

    outFile = "FILENAME " + os.getcwd() + "/" + domains[0]
    x = reconb.do_load("reporting/list")
    x.do_set(outFile+".lst")
    x.do_set("COLUMN host")
    x.do_run(None)

parser = argparse.ArgumentParser()
parser.add_argument('-a', dest='runAltDns', action='store_true', help="After recon, run AltDNS? (this requires alt-dns)")
parser.add_argument("-i", dest="filename", type=argparse.FileType('r'), help="input file of domains (one per line)", default=None)
parser.add_argument("domains", help="one or more domains", nargs="*", default=None)
parser.add_argument("-w", dest="wordlist", type=argparse.FileType('r'), help="input file of subdomain wordlist. must be in same directory as this file, or give full path", default=None)
parser.add_argument("-p", dest="permlist", type=argparse.FileType('r'), help="input file of permutations for alt-dns. if none specified will use default list.", default=None)
args = parser.parse_args()

if args.runAltDns and not altDnsPath:
    print "Error: no altDns path specified, please download from: https://github.com/infosec-au/altdns"
    exit(0)

domainList = ["centrify.com"]

if args.domains:
    domainList+=args.domains


if args.filename:
    lines = args.filename.readlines()
    lines = [line.rstrip('\n') for line in lines]
    domainList+=lines

bruteforceList = args.wordlist.name if args.wordlist else ""	

run_recon(domainList, bruteforceList)

if args.runAltDns:
    workspace = domainList[0]
    altCmd="python "+os.path.join(altDnsPath,"altdns.py")
    subdomains = os.path.join(os.getcwd(), workspace+".lst")
    permList = args.permlist.name if args.permlist else os.path.join(altDnsPath,"words.txt")
    output = os.path.join(os.getcwd(),workspace+"_output.txt")
    print "running alt-dns... please be patient :) results will be displayed in "+output
    # python altdns.py -i subdomainsList -o data_output -w permutationsList -r -s results_output.txt
    os.system('%s -i %s -o data_output -w %s -r -s %s' % (altCmd, subdomains, permList,output))
