# CervantesEsquizofrenico, DNS Recon & Silent Scan Tool

## Description

This Perl tool performs a comprehensive DNS reconnaissance on a given domain, extracting A, NS, and MX records (using part of **Dnsenum's** code).  
Additionally, it runs discreet and fast **nmap** scans on the discovered IPs, detects Web Application Firewalls (WAFs) using **WafW00f**,  
and finally extracts metadata with **MetaFinder** for additional domain intelligence.

---

## Requirements

- Perl (with modules: Net::DNS, Getopt::Long, Term::ANSIColor)  
- nmap installed and available in your PATH  
- wafw00f installed (`pip install wafw00f`)  
- metafinder installed (see [https://github.com/hiddenillusion/metafinder](https://github.com/Josue87/MetaFinder))  

---

## Installation

1. Clone or download this repository.

2. Install required Perl modules:
```bash
cpan install Net::DNS Getopt::Long Term::ANSIColor
```
3. Install required tools:

nmap: https://nmap.org/download.html

wafw00f: pip install wafw00f

metafinder: follow official installation instructions

4. Make the script executable:
```bash
chmod +x cervantesesquizofrenico.pl
```

## Usage
Dont forget to be in a virtual env if needed. Ohterwise metafinder will not work.
```bash
./cervantesesquizofrenico.pl <domain>
```
### Example:
```bash
./cervantesesquizofrenico.pl example.com
```
The script will display DNS records, run a silent nmap scan on discovered IPs, attempt WAF detection,
and extract metadata with MetaFinder saving results to a file.

## Notes
Nmap scan uses -T2 option to be fast and stealthy to avoid detection alerts.

WafW00f do not tries to bypass WAFs but can create alerts while making detections. 
Becuase of that WafW00f code is by default commented,feel free to uncomment. 

MetaFinder may take a few seconds while querying search engines like Bing and Google.

Metadata results are saved in meta_results_<domain>.txt.

## Contact
For questions or issues, feel free to contact dcentgame50@gmail.com!
