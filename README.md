# SubDomainReconV2

SubDomainRecon Python Implementation\
***massdns(passive amass + all.txt + commonspeak) -> massdns(altdns) -> subjack(results) + httprobe(results)***\
Also utilizes Bass to gather resolvers, while verifying wildcard results in both subdomains and bad resolvers.\
\
*requires google-bigquery account*


```
$ sudo python3 SubDomainRecon.py --help
usage: SubDomainRecon.py [-h] [-o OutFile] [-w Wordlist] [-a] [-g] [-s] [-t] [-c] [-v]
                         DomainName

Subdomain Recon Suite

positional arguments:
  DomainName

optional arguments:
  -h, --help   show this help message and exit
  -o OutFile   Print to output file
  -w Wordlist  Initial wordlist to use (Default all.txt)
  -a           Run Amass passive scan
  -g           Include Google BigQuery CommonSpeak in wordlist
  -s           Scan for http/s servers
  -t           Scan for subdomain takeovers
  -c           Confirm subdomains with reputable resolvers (Slow)
  -v           Enable Verbosity

```

# Install
```
sudo ./SDR-Install.sh
```
