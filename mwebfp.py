#!/usr/bin/python
#
# LowNoiseHG Web Fingerprinter v.1.0
# by F4Lc0N - LNHG - USA/Colombia
#
# Thanks to ET, ch4n, Th3R3g3nt, ch0ks and ElJeffe311 for inspiration, ideas and debugging/betatesting help.

import argparse
import socket
import re
import sys
import os
import string
import csv
import requests
import subprocess
import nmap

try:
  nm = nmap.PortScanner()
except nmap.PortScannerError:
  print('Nmap not found', sys.exc_info()[0])
  sys.exit(0)
except:
  print("Unexpected error:", sys.exc_info()[0])
  sys.exit(0)

_CIDR_RE = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$')
_DOTTED_QUAD_RE = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
errorstring = 'usage: mwebfp.py [-h] [-v] [-i INPUT_RANGE] [-f INPUT_FILE]\n                  [-o OUTPUT_DIR] [-t {XLS,CSV,XML}] [-r]\nmwebfp.py: error:'
recovering = False
httpports = []
httpsports = []

def arguments():
  global args, errorstring, httpports, httpsports, debug
  parser = argparse.ArgumentParser(description='LNHG Massive Web Fingerprinter (mwebfp) v.1.0')
  parser.add_argument('-d','--debug', action='store_true', help='show debugging info')
  inputgroup = parser.add_mutually_exclusive_group()
  inputgroup.add_argument('-i','--input-range', help='input IP CIDR range')
  inputgroup.add_argument('-n','--server-name', help='name of server (DNS name)')
  inputgroup.add_argument('-f','--input-file', help='input file containing IP addresses and/or IP ranges')
  inputgroup.add_argument('-r','--recover', action='store_true', help='recover/continue previous process')
  parser.add_argument('-p', '--http-ports', help='TCP HTTP ports (Default: 80/tcp)')
  parser.add_argument('-s', '--https-ports', help='TCP HTTPS ports (Default: 443/tcp)')
  parser.add_argument('-o','--output-dir', help='working directory')
  parser.add_argument('-t','--output-format', choices=['HTML', 'XLS', 'CSV', 'XML'], help='output report format (Default: HTML)')
  parser.add_argument('-v','--vhosts', choices=['yes', 'no'], help='choice of processing vhosts for each IP address (Default: no)')
  parser.add_argument('-w','--web-screenshots', choices=['yes', 'no'], help='choice of taking web schreenshots (Default: no)')
  args = parser.parse_args()
  debug = 0
  if not args.input_file and not args.input_range and not args.server_name and not args.recover:
    print errorstring,
    print 'at least one input is required (--input-range or --input-file or --server-name or --recover)' 
    sys.exit(0)
  if not args.output_dir:
    print errorstring,
    print 'an output directory needs to be specified. Please provide an output directory'
    sys.exit(0)
  else:
    valid_chars = "-_() %s%s" % (string.ascii_letters, string.digits)
    newdirname = ''.join(c for c in args.output_dir if c in valid_chars)
    args.output_dir = newdirname
  if args.recover:
    if args.output_format:
      print errorstring,
      print 'output format option cannot be used during recovery'
      sys.exit(0)
    if args.http_ports or args.https_ports:
      print errorstring,
      print 'additional ports options cannot be used during recovery'
      sys.exit(0)
    if args.web_screenshots:
      print errorstring,
      print 'web shcreenshots options cannot be used during recovery'
      sys.exit(0)
  if not args.web_screenshots:
    args.web_screenshots = 'no'
  if not args.vhosts:
    args.vhosts = 'no'
  if args.server_name:
    try:
      args.input_range = socket.gethostbyname_ex(args.server_name)[2][0] + '/32'
    except socket.gaierror:
      print errorstring,
      print 'invalid or unresolvable DNS server name: " ' + args.server_name + ' "'
      sys.exit(0)
  if not args.output_format:
    args.output_format = 'HTML'
  if not args.http_ports:
    args.http_ports = '80'
  else:
    addports = args.http_ports.split(",")
    finalports = []
    for port in addports:
      try: 
        intport = int(port)
        if intport < 0 or intport > 65535:
          print errorstring,
          print 'invalid HTTP port (must be between 0 and 65535): " ' + port + ' "'
          sys.exit(0)
      except ValueError:
        print errorstring,
        print 'invalid addition port: " ' + port + ' "'
        sys.exit(0)
      finalports.append(port)
    if '80' not in finalports:
      finalports.append('80')
      finalports.sort(key=int)
    initial = 0
    httpports = finalports
    for port in finalports:
      if initial == 0:
        args.http_ports = port
        initial = 1
      else:
        args.http_ports = args.http_ports + ',' + port 
  if not args.https_ports:
    args.https_ports = '443'
  else:
    addports = args.https_ports.split(",")
    finalports = []
    for port in addports:
      try:
        intport = int(port)
        if intport < 0 or intport > 65535:
          print errorstring,
          print 'invalid HTTPS port (must be between 0 and 65535): " ' + port + ' "'
          sys.exit(0)
      except ValueError:
        print errorstring,
        print 'invalid addition port: " ' + port + ' "'
        sys.exit(0)
      finalports.append(port)
    if '443' not in finalports:
      finalports.append('443')
      finalports.sort(key=int)
    initial = 0
    httpsports = finalports
    for port in finalports:
      if initial == 0:
        args.https_ports = port
        initial = 1
      else:
        args.https_ports = args.https_ports + ',' + port
  if args.input_range:
    if not validate_cidr(args.input_range) and not validate_ip(args.input_range):
      print errorstring,
      print 'the provided CIDR IP range is NOT valid. Please provide a valid CIDR IP range (i.e. 10.0.0.0/24)'
      sys.exit(0)
  if args.input_file:
    if not os.path.exists(args.input_file):
      print errorstring,
      print 'filename provided (' + args.input_file + ') does not exist. Please provide the correct name for your IP range file'
      sys.exit(0)
    if os.stat(args.input_file)[6]==0:
      print errorstring,
      print 'The IP range file you provided (' + args.input_file + ') is empty. Please provide a valid IP range file'
      sys.exit(0)

def ip2network(ip):
  quads = ip.split('.')
  netw = 0
  for i in range(4):
    netw = (netw << 8) | int(len(quads) > i and quads[i] or 0)
  return netw

def ip2long(ip):
  if not validate_ip(ip):
    return None
  quads = ip.split('.')
  if len(quads) == 1:
    quads = quads + [0, 0, 0]
  elif len(quads) < 4:
    host = quads[-1:]
    quads = quads[:-1] + [0, ] * (4 - len(quads)) + host
  lngip = 0
  for q in quads:
    lngip = (lngip << 8) | int(q)
  return lngip

def validate_ip(s):
  if _DOTTED_QUAD_RE.match(s):
    quads = s.split('.')
    for q in quads:
      if int(q) > 255:
        return False
    return True
  return False

def validate_cidr(s):
  if _CIDR_RE.match(s):
    ip, mask = s.split('/')
    if validate_ip(ip):
      if int(mask) > 32:
        return False
    else:
      return False
    return True
  return False
 
def vhosts(ip):
  r = requests.get('http://ip.robtex.com/' + ip + '.html')
  vhoststemp = re.findall(r'<li><a href="//.+".+\>(.+)</a></li>',r.text)
  vhosts = []
  for vhost in vhoststemp:
    if '*' not in str(vhost):
      vhosts.append(str(vhost))
  vhosts_set = set(vhosts)
  vhosts = list(vhosts_set)
  return vhosts

def createcsv(csvfile):
  global args
  ofile  = open(csvfile, 'w')
  writer = csv.writer(ofile)
  if args.web_screenshots == 'yes':
    writer.writerow(['IP ADDRESS','PORT','STATE','HOSTNAME','TITLE','FAVICON','METHODS','HEADERS','SERVER','CAPTURE FILENAME'])
  else:
    writer.writerow(['IP ADDRESS','PORT','STATE','HOSTNAME','TITLE','FAVICON','METHODS','HEADERS','SERVER'])
  ofile.close()

def writecsv(csvfile,row):
  global args
  ofile  = open(csvfile, 'a')
  writer = csv.writer(ofile)
  writer.writerow(row)
  ofile.close()

def main():
  global args, errorstring, httpports, httpsports, debug, recovering, csvfile
  arguments()
  if debug:
    print 'DEBUG: RECEIVED ARGUMENTS AFTER PROCESSING:'
    print '  Debug:',args.debug
    print '  Input Range:',args.input_range
    print '  Input File:',args.input_file
    print '  Output Directory (Sanitized):',args.output_dir
    print '  Output Format:',args.output_format
    print '  Recover:',args.recover
    print '  HTTP Ports:',args.http_ports
    print '  HTTPS Ports:',args.https_ports
    print '  VHosts:',args.vhosts
    print '  Web Screenshots:',args.web_screenshots
  if args.recover and not os.path.exists(args.output_dir):
    print errorstring,
    print 'directory for recovery process not found'
    sys.exit(0)
  if os.path.exists(args.output_dir):
    print 'Using existing directory: ',args.output_dir
    if args.recover:
      if not os.path.exists(args.output_dir + '/.status'):
        print errorstring,
        print 'Recovery not possible: Recovery status file not found at \'' + args.output_dir + '\''
        sys.exit(0)
      if not os.path.exists(args.output_dir + '/.allips'):
        print errorstring,
        print 'Recovery not possible: Recovery target file not found at \'' + args.output_dir + '\''
        sys.exit(0)
      statusfile = open(args.output_dir + '/.status', 'r')
      status = statusfile.readline().strip('\n')
      statusfile.close()
      ststage = int(re.findall(r'(\d+)-',status)[0])
      stcode = int(re.findall(r'-(\d+)',status)[0])
      recovering = True
      if debug:
        print 'DEBUG: Recovering: Stage: ' + str(ststage) + ' Code: ' + str(stcode)
  else:
    print 'Creating output directory: ',args.output_dir
    os.makedirs(args.output_dir)  
  csvfile = args.output_dir + '/mwebfp-' + args.output_dir + '.csv'
  createcsv(csvfile)
  cidr_ranges = []
  if args.input_file:
    try:
      rangefile = open(args.input_file, 'r')
    except IndexError:
      print errorstring,
      print 'something is wrong with the provided filename'
      sys.exit(0)
    for line in rangefile.readlines():
      line = line.rstrip('\n')
      if not validate_cidr(line) and not validate_ip(line):
        print errorstring,
        print 'provided CIDR IP range file contains invalid lines. Verify file contents: " ' + line + ' "'
        sys.exit(0)
      else:
        if '/' not in line:
          line = line + '/32'
        cidr_ranges.append(line)
  if args.input_range:
    if '/' not in args.input_range:
       args.input_range = args.input_range + '/32'
    cidr_ranges.append(args.input_range)
  if debug: print 'DEBUG: Initial CIDR ranges list: ',cidr_ranges
  if recovering == False:
    all_ips = []
    for iprange in cidr_ranges:
      nm1 = nmap.PortScanner()
      nm1.scan(iprange, arguments='-sL -vvv -n -P0')
      allhosts = []
      for host in nm1.all_hosts():
        all_ips.append(str(host))
      for i in range(len(all_ips)):
        all_ips[i] = "%3s.%3s.%3s.%3s" % tuple(all_ips[i].split("."))
      all_ips.sort()
      for i in range(len(all_ips)):
        all_ips[i] = all_ips[i].replace(" ", "")
    targetfile = open(args.output_dir + '/.allips', 'w')
    for ip in all_ips:
      targetfile.write("%s\n" % ip)
    targetfile.close()
  else:
    all_ips = []
    with open(args.output_dir + '/.allips') as f:
      all_ips = f.read().splitlines()
    for ip in all_ips:
      if not validate_ip(ip):
        print errorstring,
        print 'Recovery not possible: Recovery target file is corrupted'
        sys.exit(0)
  if debug: print 'ips (All IPs) = ',all_ips
  numips = len(all_ips)
  print 'Loaded ' + str(numips) + ' IP addresses to scan' 
  scanports = args.http_ports + ',' + args.https_ports
  http_ports = args.http_ports.split(',')
  https_ports = args.https_ports.split(',')
  scanports_list = scanports.split(',')
  if debug: print 'TCP Ports to scan (HTTP and HTTPS):',scanports
  for ip in all_ips:
    vhostsip = []
    if args.vhosts == 'yes':
      print 'IP Address = ' + ip + ' (also checking virtual hosts)'
      vhostsip = vhosts(ip)
    else:
      print 'IP Address = ' + ip
    print '   NMap heavylifting ... (please be patient)'
    nm2 = nmap.PortScanner()
    nm2.scan(ip,arguments='-sT -P0 -vvv -n -T4 -oN ' + args.output_dir + '/mwebfp-nmap-' + ip + '.txt --script=http-favicon --script=http-headers --script=http-methods --script=http-title -p' + scanports)
    for port in scanports_list:
      portstate = nm2[ip]['tcp'][int(port)]['state']
      print '   Processing port ' + port + '\t->\t' + portstate
      if portstate == 'open':
        try:
          title = str(nm2[ip]['tcp'][int(port)]['script']['http-title'])
        except:
          title = '<No Title>'
        try:
          favicon = str(nm2[ip]['tcp'][int(port)]['script']['http-favicon'])
        except:
          favicon = '<No Favicon>'
        try:
          methods = str(nm2[ip]['tcp'][int(port)]['script']['http-methods'])
        except:
          methods = '<No Methods>'
        try:
          headers = str(nm2[ip]['tcp'][int(port)]['script']['http-headers']).strip(' ').lstrip('\n').strip('\n').lstrip(' ').replace('\n  ','\n')
          server = re.findall(r'Server: (\S+)',headers)[0]
        except:
          headers = '<No Headers>'
          server = '<No Server>'
        if args.web_screenshots == 'yes':
          print '      Capturing screenshot ...',
          if port in http_ports:
            try:
              fname = 'mwebfp-capture---http-' + ip + '-NoHostname-p' + port + '.png'
              filename = args.output_dir + '/' + fname
              subprocess.call(['cutycapt','--url=http://' + ip + '/','--out=' + filename,'--out-format=png'])
            except:
              pass
          if port in https_ports:
            try:
              fname = 'mwebfp-capture---https-' + ip + '-NoHostname-p' + port + '.png'
              filename = args.output_dir + '/' + fname
              subprocess.call(['cutycapt','--url=https://' + ip + '/','--out=' + filename,'--out-format=png','--insecure'])
            except:
              pass
          writecsv(csvfile,[ip,port,'open','<No Hostname>',title,favicon,methods,headers,server,fname])
        else:
          writecsv(csvfile,[ip,port,'open','<No Hostname>',title,favicon,methods,headers,server])
        if args.vhosts == 'yes' and len(vhostsip) > 0:
          for vhost in vhostsip:
            nm3 = nmap.PortScanner()
            nm3.scan(vhost,arguments='-sT -sV -P0 -vvv -n -T4 -oN ' + args.output_dir + '/mwebfp-nmap-' + ip + '-' + vhost + '-p' + port + '.txt --script=http-favicon --script=http-headers --script=http-methods --script=http-title -p' + port)
            try:
              title = str(nm3[ip]['tcp'][int(port)]['script']['http-title'])
            except:
              title = '<No Title>'
            try:
              favicon = str(nm3[ip]['tcp'][int(port)]['script']['http-favicon'])
            except:
              favicon = '<No Favicon>'
            try:
              methods = str(nm3[ip]['tcp'][int(port)]['script']['http-methods'])
            except:
              methods = '<No Methods>'
            try:
              headers = str(nm3[ip]['tcp'][int(port)]['script']['http-headers']).strip(' ').lstrip('\n').strip('\n').lstrip(' ').replace('\n  ','\n')
              server = re.findall(r'Server: (\S+)',headers)[0]
            except:
              headers = '<No Headers>'
              server = '<No Server>'
            if args.web_screenshots == 'yes':
              if port in http_ports:
                try:
                  fname = 'mwebfp-capture---http-' + ip + '-' + vhost + '-p' + port + '.png' 
                  filename = args.output_dir + '/' + fname
                  subprocess.call(['cutycapt','--url=http://' + vhost + '/','--out=' + filename,'--out-format=png'])
                except:
                  pass
              if port in https_ports:
                try:
                  fname = 'mwebfp-capture---https-' + ip + '-' + vhost + '-p' + port + '.png'
                  filename = args.output_dir + '/' + fname
                  subprocess.call(['cutycapt','--url=https://' + vhost + '/','--out=' + filename,'--out-format=png','--insecure'])
                except:
                  pass
              writecsv(csvfile,[ip,port,'open',vhost,title,favicon,methods,headers,server,fname])
            else:
              writecsv(csvfile,[ip,port,'open',vhost,title,favicon,methods,headers,server])
        print 'Done.'
      else:
        writecsv(csvfile,[ip,port,str(portstate)])
  print 'Done. Go check your report file !'

if __name__ == "__main__":
    main()
