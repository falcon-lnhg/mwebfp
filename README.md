# LNHG - Massive Web Fingerprinter (mwebfp)

## Introduction

The "**LowNoiseHG (LNHG) Massive Web Fingerprinter**" ("**mwebfp**" from now on) was conceived in July 2013 after realizing the usefulness of webserver screenshots to pentesters, during an engagement with large external or internal IP address ranges, as a quick means of identification of critical assets, easily-exploitable services, forgotten/outdated servers and basic network architecture knowledge of the target.

## Description

The basic operation of **mwebfp** consists of the processing of an input (targets and TCP ports) that is then used to identify open web server ports with the help of a powerful portscanner (nmap). All ports found open are then analyzed (on HTTP and HTTPS) and all relevant webserver information is recorded, as well as a screenshot of the rendered webpage (as if it is seen from a broswer). 

## Special Features

- Input
  - Target(s) can be IP address(es), IP address range(s), server name(s), etc.
  - Target(s) can be provided directly on the command-line or on a file
- Port Definition
  - Default ports are 80 (HTTP) and 443 (HTTPS), but any port can be easily configured at runtime
- Output
  - All output files and related support files for the scan are saved on a directory configured at runtime by the user
  - Currently, **mwebfp** exports results on a CSV file (Easily usable on MS Excel) only
- Virtual Hosts
  - If requested at runtime, **mwebfp** will find all virutally hosted domains and webpages for the target server
- Webserver Screenshots
  - If requested at runtime, **mwebfp** will grab screenshots of all found web pages (Graphical UI under Linux is required)

## Parameters
```
# LowNoiseHG Massive Web Fingerprinter
# by F4Lc0N - LNHG - USA/Colombia
#
# Thanks to Efrain Torres (ET), David Llorens (ch4n), Balazs Makany, and Adrian Puente (ch0ks) for inspiration, ideas and debugging/beta-testing help.

usage: mwebfp.py [-h] [-d]
                 [-i INPUT_RANGE | -n SERVER_NAME | -f INPUT_FILE | -r]
                 [-p HTTP_PORTS] [-s HTTPS_PORTS] [-o OUTPUT_DIR]
                 [-t {HTML,XLS,CSV,XML}] [-v {yes,no}] [-w {yes,no}]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           show debugging info
  -i INPUT_RANGE, --input-range INPUT_RANGE
                        input IP CIDR range
  -n SERVER_NAME, --server-name SERVER_NAME
                        name of server (DNS name)
  -f INPUT_FILE, --input-file INPUT_FILE
                        input file containing IP addresses and/or IP ranges
  -r, --recover         recover/continue previous process
  -p HTTP_PORTS, --http-ports HTTP_PORTS
                        TCP HTTP ports (Default: 80/tcp)
  -s HTTPS_PORTS, --https-ports HTTPS_PORTS
                        TCP HTTPS ports (Default: 443/tcp)
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        working directory
  -t {HTML,XLS,CSV,XML}, --output-format {HTML,XLS,CSV,XML}
                        output report format (Default: HTML)
  -v {yes,no}, --vhosts {yes,no}
                        choice of processing vhosts for each IP address
                        (Default: no)
  -w {yes,no}, --web-screenshots {yes,no}
                        choice of taking web schreenshots (Default: no)
```
## Current State of Development

As most of the R&D done in **LowNoiseHG (LNHG)** this tool was designed and developed only for its usefulness and with no economic funds or time allocated to it. All development has been done on personal time only, and it will continue as interesting featurs come up, and if time is available taking into account other projects.

The current version works very well, even though there are still some minor wrinkles (bugs) to iron, and some basic features that can be improved:

- Features on the works:
  - The *recovery* feature is non-functional yet
  - The output format for the report is currently CSV, HTML is done but not included yet. All others are non-functional

- Known bugs:
  - There is a bug on the *virtual host identification* process, that has been identified and will be fixed soon
 
## License

## Requirements

In order to run **mwebfp** "out-of-the-git", with all options enabled, you will need:

- Python
- nmap
- python-nmap
- cutycapt (You will need a new version to be able to capture HTTPS pages. A walkthrough for this will be available soon here)
- A graphical interface (GUI) on the \*nix server you are running the script (I assume Linux)

**NOTE: mwebfp** has been developed and tested on Kali, Ubuntu and Debian. I am sure **YOU** can make it work in other platforms of your choice ;)

## Developers

### [LowNoiseHG] (http://www.lownoisehg.org):

- F4Lc0N - falcon [at] lownoisehg.org

