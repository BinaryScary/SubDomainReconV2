# SubDomainReconV2

SubDomainRecon Python Implementation\
***massdns(passive amass + all.txt + commonspeak) -> massdns(altdns) -> subjack(results) + httprobe(results)***\
Utalizes Bass to gather resolvers, verifies wildcard results in both subdomains and bad resolvers.\
\
*requires google-bigquery account*


```
$ sudo python3 SubDomainRecon.py --help
usage: SubDomainRecon.py [-h] [-o OutFile] [-v] [-s] [-t] [-c] DomainName

Subdomain Recon Suite

positional arguments:
  DomainName

optional arguments:
  -h, --help  show this help message and exit
  -o OutFile  Print to output file
  -v          Enable Verbosity
  -s          Scan for http/s servers
  -t          Scan for subdomain takeovers
  -c          confirm subdomains with reputable resolvers
```

# Install
```
sudo ./SDR-Install.sh
```
