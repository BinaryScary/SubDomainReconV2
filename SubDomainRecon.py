#!/usr/bin/python3

import sys
import socket
import logging
import argparse
import os
import subprocess
import glob
import time
import wget
import dns.resolver
import concurrent.futures
import threading
import re

# dependencies: amass, massdns, altdns, commonspeak, bass resolver, subjack, httprobe
# lists: all.txt

gCloudComm = 'commonspeak-******'
scriptLoc = os.path.dirname(os.path.realpath(__file__))

def checkWildCard(domain):
    try:
        socket.gethostbyname("abcdefghijklmnopqrstuvwxyz9999.%s"%domain)
        return True
    except socket.error:
        return False

# gather resolvers with bass
def runBass(domain):
    cmd = ['/usr/bin/python3','%s/bass/bass.py'%scriptLoc,'-d','%s'%domain,'-o','%s/wordlists/resolvers.txt'%scriptLoc] 
    results = subprocess.run(cmd)
    return results.returncode

# get a list of public resolvers (less false positives)
def getPubResolvers():
    cmd = ['wget','https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt','-O','%s/wordlists/resolvers.txt' % scriptLoc]
    results = subprocess.run(cmd)

# initial amass passive recon
def runAmass(domain):
    cmd = '/snap/bin/amass enum --passive -d %s' % domain
    results = subprocess.run(cmd.split(),stdout=subprocess.PIPE)

    # run massdns on amass results
    cmd = ['%s/massdns/bin/massdns'%scriptLoc,'-r','%s/wordlists/resolvers.txt'%scriptLoc,'-t','A','-o','S']
    results = subprocess.run(cmd, stdout=subprocess.PIPE, input=results.stdout)

    return results.stdout

# Brute force subdomains using subbrute with all.txt
def runAll(domain):
    cmd = ['%s/massdns/scripts/subbrute.py'%scriptLoc,'%s/wordlists/all.txt'%scriptLoc,domain]
    results = subprocess.run(cmd,stdout=subprocess.PIPE)

    cmd = ['%s/massdns/bin/massdns'%scriptLoc,'-r','%s/wordlists/resolvers.txt'%scriptLoc,'-t','A','-o','S'] 
    results = subprocess.run(cmd, stdout=subprocess.PIPE, input=results.stdout)

    return results.stdout

# check time difference in modified dates to see if commonspeak compilation is old
def isCommOld():
    gFiles = glob.glob('%s/commonspeak/stackoverflow/output/compiled/*'%scriptLoc)
    lFile = max(gFiles, key=os.path.getmtime)
    t1 = os.path.getmtime(lFile)
    t2 = time.time()
    if (t2 - int(t1)) > 604800:
        return True
    return False

# grab commonspeak subdomains from stack overflow
def updateComm():
    cmd = ['bash','%s/stackoverflow-subdomains.sh'%scriptLoc,gCloudComm]
    subprocess.run(cmd,cwd='%s/commonspeak/stackoverflow' % os.getcwd())

# concat common words with domain
def commDomains(domain):
    gFiles = glob.glob('%s/commonspeak/stackoverflow/output/compiled/*subdomains.txt'%scriptLoc)
    lFile = max(gFiles, key=os.path.getmtime)    
    wFile = open(lFile,"r")
    wordlist = wFile.read().split()
    wFile.close()
    dList = []

    for word in wordlist:
        if not word.strip(): 
            continue
        dList.append('%s.%s' %(word,domain))
    return dList

# brute force commonspeak domains with massdns
def runComm(domain):
    commList = commDomains(domain)
    commStr = '\n'.join(commList).encode()

    cmd = ['%s/massdns/bin/massdns'%scriptLoc,'-r','%s/wordlists/resolvers.txt'%scriptLoc,'-t','A','-o','S']
    results = subprocess.run(cmd, stdout=subprocess.PIPE, input=commStr)

    return results.stdout

# possible other solutions to false positives problem:
# - remove ips that show up a majority of the time, will still have to print them out incase subdomains are part of a VHOST
# - unbounded server local dns

# wildcard check on resolver list
def runNXFilter(domain):
    # generate wildcards
    count = sum(1 for line in open('%s/wordlists/resolvers.txt'%scriptLoc))
    wildcards = []
    for i in range(count):
        wildcards.append("%dabcdefgh.%s"%(i,domain))
    wildStr = '\n'.join(wildcards).encode()

    # run wildcard on each resolver
    # NXDOMAIN responses dictact a good resolver
    cmd = ['%s/massdns/bin/massdns'%scriptLoc,'--predictable','-r','%s/wordlists/resolvers.txt'%scriptLoc,'-t','A','-o','Sqrm']
    results = subprocess.run(cmd, stdout=subprocess.PIPE, input=wildStr)

    # only add nameservers with respond with NXDOMAIN
    reGroups = re.findall('(?P<IP>([0-9]{1,3}[\.]){3}[0-9]{1,3}).*NXDOMAIN',results.stdout.decode())

    nameservers = []
    for ip in reGroups:
        nameservers.append(ip[0])
    
    # remove duplicates
    nameservers = list(set(nameservers))

    # write resolvers to file
    with open('%s/wordlists/resolvers.txt'%scriptLoc, 'w') as f:
        for item in nameservers:
            f.write("%s\n" % item)

    return nameservers

# multithreaded domain prover
def filterDomains(domains):
    # reputable resolvers
    resolvers = ['8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','208.67.220.220','208.67.222.222','9.9.9.9','149.112.112.112']

    domainTuples = list(zip(resolvers,domains))

    gDomains = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        executor.map(lambda dt: filterDomainsHelper(gDomains,dt),domainTuples)
    return gDomains

# filter out bad domains from list
def filterDomainsHelper(gDomains,dt):
    resolver = dt[0]
    domain = dt[1]

    dnsResolver = dns.resolver.Resolver()
    dnsResolver.nameserver = [resolver]
    dnsResolver.timeout = 3
    dnsResolver.lifetime = 3

    # if resolver can't resolve parent domain return
    try:
        dnsResolver.query(domain,"A")
        gDomains.append(domain)
    except:
        return

def runAlt(mDomains):
    # write domains to file
    tFile = 'tempDomains.txt'
    with open(tFile, 'w') as f:
        for item in mDomains:
            f.write("%s\n" % item)

    temp = "tempAltDomains.txt"
    cmd = ['altdns','-i',tFile,'-o',temp,'-w','%s/wordlists/words.txt'%scriptLoc]
    subprocess.run(cmd)

    # can't fit altdns file into memory pipe file instead
    cmd = ['%s/massdns/bin/massdns'%scriptLoc,'-r','%s/wordlists/resolvers.txt'%scriptLoc,'-t','A','-o','S']
    with open(temp, 'rb', 0) as a:
        results = subprocess.run(cmd, stdin=a, stdout=subprocess.PIPE)

    os.remove(temp)
    os.remove(tFile)
    # return results.stdout
    return results.stdout

# parse massdns output
# extract domains from massDNS and remove period at end
def parseM(lst):
    return [i.split(" ")[0][:-1] for i in lst.decode().split("\n")]

# runs httprobe on list
def runHttprobe(domains):
    cmd = ['%s/go/bin/httprobe'% os.path.expanduser("~"),'-c','100','-t','1500'] 
    results = subprocess.run(cmd, stdout=subprocess.PIPE, input="\n".join(domains).encode())
    return results.stdout

def runSubjack(mDomains):
    # write domains to file
    tFile = '%s/tempDomains.txt'%scriptLoc
    with open(tFile, 'w') as f:
        for item in mDomains:
            f.write("%s\n" % item)

    home = os.path.expanduser("~")
    cmd = ['%s/go/bin/subjack'%home,'-t','100','-timeout','30','-ssl','-w',tFile,'-c','%s/go/src/github.com/haccer/subjack/fingerprints.json'%home]
    results = subprocess.run(cmd,stdout=subprocess.PIPE)

    os.remove(tFile)
    return results.stdout

if __name__ == "__main__":
    # flags
    domain = None
    outputFile = None
    http = False
    takeover = False
    confirm = False
    # output
    mDomains = []
    httpServers = b''
    takeover = b'' 
    stdOutput = ""

    # setup and parse arguments
    parser = argparse.ArgumentParser(description='Subdomain Recon Suite')
    parser.add_argument('domain',metavar='DomainName',type=str)
    parser.add_argument('-o', help='Print to output file', metavar='OutFile',type=str)
    parser.add_argument('-v', help='Enable Verbosity', action='store_true')
    parser.add_argument('-s', help='Scan for http/s servers', action='store_true')
    parser.add_argument('-t', help='Scan for subdomain takeovers', action='store_true')
    parser.add_argument('-c', help='confirm subdomains with reputable resolvers', action='store_true')
    args = parser.parse_args()

    domain = args.domain

    http = args.s
    takeover = args.t
    confirm = args.c

    # setup outputfile
    if args.o != None:
        outputFile = args.o

    # setup logging/verbosity
    if args.v:
        # will print 'debug', 'info', 'info', 'error' and 'warning' logs to stderr
        logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
    else:
        # will print 'info', 'error' and 'warning' logs to stderr
        logging.basicConfig(format="%(levelname)s: %(message)s",level=logging.INFO)

    logging.info("Checking for Wildcard DNS Configurations")
    if checkWildCard(domain):
        logging.error("Wildcard DNS detected")
        quit()
    
    logging.info("Gathering Resolvers")
    # runBass(domain)

    # public resolvers produce less false positives
    getPubResolvers()

    logging.info("Filtering Bad Resolvers")
    resolvers = runNXFilter(domain)

    logging.info("Amass initial recon")
    mAmass = runAmass(domain)

    logging.info("Brute forcing all.txt with massdns")
    mAll = runAll(domain)

    logging.info("Brute forcing commonspeak with massdns")
    if isCommOld():
        updateComm()
    mComm = runComm(domain)

    # extract domains from massDNS and remove period at end
    mDomains = parseM(mAll + mAmass + mComm)

    logging.info("Generating AltDNS and brute forcing with results")
    mAlt = runAlt(mDomains)

    # append altdns domains to results
    mDomains += parseM(mAlt)

    # remove duplicate list entries
    mDomains = list(set(mDomains))

    # -c flag
    if confirm:
        logging.info("Ensuring subdomains with reputable resolvers")
        mDomains = filterDomains(mDomains)

    # append to output
    stdOutput+="[-] Subdomains:\n"
    stdOutput+="\n".join(mDomains)+"\n"

    if(outputFile != None):
        with open('%s.domains' % outputFile, 'w') as f:
            for item in mDomains:
                f.write("%s\n" % item)

    # -s flag
    if http:
        logging.info("Scanning for http/s servers")
        httpServers = runHttprobe(mDomains)
        if(outputFile != None and httpServers != b''):
            with open('%s.http' % outputFile, 'w') as f:
                f.write(httpServers.decode())
        stdOutput+="[-] HTTP/S Servers:\n"
        stdOutput+=httpServers.decode()

    # -t flag
    if takeover:
        logging.info("Scanning for subdomain takeovers")
        takeoverDomains = runSubjack(mDomains)
        if(outputFile != None and takeoverDomains != b''):
            with open('%s.takeovers' % outputFile, 'w') as f:
                f.write(takeoverDomains.decode())
        stdOutput+="[-] SubDomain Takeovers:\n"
        stdOutput+=takeoverDomains.decode()

    # print result output
    print(stdOutput)