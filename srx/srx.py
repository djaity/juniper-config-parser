#!/usr/bin/python
# -*- coding: utf-8 -*-
# ----------------------------------------------------
# Creation Date : Jan/14/2017
# Author : JT Graveaud
# ----------------------------------------------------
# this script needs the following libraries:

# ----------------------------------------------------
# on Mac OS - El Capitan
# $ sudo easy_install lxml
# $ sudo easy_install netaddr
# $ sudo easy_install beautifulsoup4
# $ sudo easy_install pillow (only needed to generate images)
# on Sierra, to install 'brew'
# ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" < /dev/null 2> /dev/null ; brew install caskroom/cask/brew-cask 2> /dev/null
# If the screen prompts you to enter a password, please enter your Mac's user password to continue

# $ brew install graphviz

# ----------------------------------------------------
# on CentOS
# yum install python-lxml
# yum install python-netaddr
# yum install python-beautifulsoup4
# yum install "graphviz*"
# yum install python-pillow

# ----------------------------------------------------
# on Ubuntu
# apt-get install python-lxml
# apt-get install python-netaddr
# apt-get install python-bs4
# apt-get install python-pil
# apt-get install graphviz

# ------------------
# useful command lines:
# ------------------
# To generate the xml file from the SRX (get srx config)
# $ ssh ucp-ro@<srx ip 172.31> "show configuration | display xml" > srx.xml
# $ ssh ucp-ro@<srx ip 172.31> "show arp" > srx_arp.xml
# To get SRX hits counts
# $ ssh ucp-ro@<srx ip 172.31> "show security policies hit-count" > srx.cnt

# To generate the graphe of all rules
# $ for graph in `srx.py -rulescomb`; do srx.py -rulestree $graph > graphviz/$graph.viz; dot graphviz/$graph.viz -Tjpg -o graphs/$graph.jpg; done

# To make a single image with all images generated : the goal is to be able to print it on A0 format
# $ srx.py -mergeall graphviz


# for graph in `srx.py -rulescomb`; do srx.py -rulestree $graph -port junos-https > junoshttps/$graph.viz; dot junoshttps/$graph.viz -Tjpg -o junoshttps/$graph.jpg; done
# $ srx.py -mergeall junoshttps


# To graph the link between Zones
# rm graphTEST.jpg; srx.py -zpolicies -graphviz > graphTEST.viz; neato graphTEST.viz  -Tjpg -o graphTEST.jpg
# ------------------

from bs4 import BeautifulSoup as Soup
import argparse
import code
import pprint
import netaddr # https://media.readthedocs.org/pdf/netaddr/latest/netaddr.pdf
import os, sys
#from PIL import Image, ImageFont, ImageDraw, ImageOps

import pexpect
import getpass
from time import sleep
import sys
from os.path import isfile, join, dirname, abspath

sys.path.append(os.path.dirname(os.path.abspath(__file__+'/..'))+'/common')
import pysec

#print "------------------"
#temporary dev code reminder
pp = pprint.PrettyPrinter(indent=2)
#pp.pprint(policies)
#print "------------------"

# -------------------------------
# Parameters passed in command line
# -------------------------------

# init the parser from command line
cmd_parser = argparse.ArgumentParser(description='Parser of SRX configuration file')

# list of paramters
cmd_parser.add_argument('-lzone', action='store_true',
                        help='list all Zones and provides the number of IPs')
cmd_parser.add_argument('-laddrset', action='store_true',
                        help='list all Zones and provides the number of address-set')
cmd_parser.add_argument('-lsnat', action='store_true',
                        help='list all NAT Source')
cmd_parser.add_argument('-ldnat', action='store_true',
                        help='list all NAT Destination')
cmd_parser.add_argument('-zoneip', default=None,
                        help='list IPs in a zone (can work with -allip)')
cmd_parser.add_argument('-zoneaddrset', default=None,
                        help='list address-set in a zone')
cmd_parser.add_argument('-allip', action='store_true',
                        help='list all IPs')
cmd_parser.add_argument('-oneline', action='store_true',
                        help='list all rules in one line')
cmd_parser.add_argument('-noheader', action='store_true',
                        help='do not display header when using -oneline option')
cmd_parser.add_argument('-alladdrset', action='store_true',
                        help='list all Address Set')
cmd_parser.add_argument('-zpolicies', action='store_true',
                        help='list zones for each policy')
cmd_parser.add_argument('-graphviz', action='store_true',
                        help='instructions to display graph of "zpolicies"')
cmd_parser.add_argument('-rulestree', default=None,
                        help='display the rules tree for a given zone <from_zone-to_zone>')
cmd_parser.add_argument('-port', default=None,
                        help='if used with -rulestree, display the rules tree only for the given port')
cmd_parser.add_argument('-rulescomb', action='store_true',
                        help='list all combinaisons to display graph with graphviz')
cmd_parser.add_argument('-onlyfrom', action='store_true',
                        help='combined with option -rulecomb to display only From zone')
cmd_parser.add_argument('-onlyto', action='store_true',
                        help='combined with option -rulecomb to display only To zone')
cmd_parser.add_argument('-getconf', action='store_true',
                        help='Get SRX configuration + hit counters, to be used with -oneline')
cmd_parser.add_argument('-mergeall', default=None,
                        help='merge all images generated in <mergeall> directory into one jpeg')
cmd_parser.add_argument('-dspwarn', action='store_true',
                        help='Display warning messages while parsing the configuration file')
cmd_parser.add_argument('-dspstat', action='store_true',
                        help='Display statistics about the configuration')
cmd_parser.add_argument('-graphroute', action='store_true',
                        help='Display graphviz code of the static routes')
cmd_parser.add_argument('-array', default=None,
                        help='display the array provided')
cmd_parser.add_argument('-ipaddrbook', default=None,
                        help='display the list of IPs of an address-set or address')
cmd_parser.add_argument('-keypwfile', default=None,
                        help='Specify the password key name (SRX password encoded file), by default the value is "key_default.enc"')
cmd_parser.add_argument('-srx_ip', default=None,
                        help='Overwrite the SRX\'s IP address, by default the value is set in srx.conf ')

PARAM = cmd_parser.parse_args()

# =======================================================================
# Short list of internal Functions
# =======================================================================
def col_red(prt): return("\033[91m{}\033[00m" .format(prt))
def col_green(prt): return("\033[92m{}\033[00m" .format(prt))
def col_yellow(prt): return("\033[93m{}\033[00m" .format(prt))
def col_light_purple(prt): return("\033[94m{}\033[00m" .format(prt))
def col_blue(prt): return("\033[94m{}\033[00m" .format(prt))
def col_purple(prt): return("\033[95m{}\033[00m" .format(prt))
def col_cyan(prt): return("\033[96m{}\033[00m" .format(prt))
def col_light_grey(prt): return("\033[97m{}\033[00m" .format(prt))
def col_bg_gray(prt): return("\033[47m{}\033[00m" .format(prt))
def col_black(prt): return("\033[98m{}\033[00m" .format(prt))

# wrap the color in style name
def dsp_banner(str):
  return col_blue(str)
def dsp_section(str):
  return col_bg_gray(str)
def dsp_var(str):
  return col_purple(str)

def scan_tag(tagname, searchtag, single_value=0):
  '''Parse a part of the XML structure
     and return the tag children
  '''
  tags = []
  for child in tagname.children:
    if child.name == None:
      continue
    if child.name == searchtag:
      tags.append(child.children)
  if single_value == 1:
    for field in tags[0]:
      return field
  return tags

def print_warn(text):
  global PARAM
  if PARAM.dspwarn:
    print col_red("Warning: "+text)


def graphviz_header():
  return """digraph ap_graphs {
  graph [ overlap=false]; size="1600,1200";
  node [shape=rect fontsize=32];
"""

def graphviz_footer():
  return """
}
"""


def get_bracket_array(array, field=None):
  ''' Return the max and the min number of values across all elements of an array '''
  len_min = array[array.keys()[0]]
  len_max = 0
  sum = 0
  for a in array.keys():
    if field:
      if len(array[a][field]) > len_max:
        len_max = len(array[a][field])
      if len(array[a][field]) < len_min:
        len_min = len(array[a][field])
      sum += len(array[a][field])
    else:
      if len(array[a]) > len_max:
        len_max = len(array[a])
      if len(array[a]) < len_min:
        len_min = len(array[a])
      sum += len(array[a])
  return (len_min, len_max, sum)

def dsp_bracket_array(var):
  (min, max, sum) = var
  return 'min:',min, ' / max:',max, ' / sum:',sum

def get_separator(title):
  if title:
    return '------------------------------------------------' \
      + "\n" + title + "\n" + \
      '------------------------------------------------'
  else:
    return '------------------------------------------------'


def get_ips_from_address_book(addr_str):
  ''' get all ip addresses implied in an address-book recursively'''
  global address_set_by_name
  global address_by_name
  address_book = []
  if address_set_by_name.has_key(addr_str):
    for addr_set in address_set_by_name[addr_str]:
      elements = get_ips_from_address_book(addr_set)
      if len(elements)>0:
        for elem in elements:
          address_book.append(elem)
  elif address_by_name.has_key(addr_str):
    for address in address_by_name[addr_str]:
      address_book.append(address)
  return address_book

def read_conf(param_name, conf_file_name='srx.conf'):
  with open(conf_file_name, 'r') as fd:
    conf_lines = fd.read()
    for line in conf_lines.split("\n"):
      conf = line.split()
      if len(conf) == 3:
        if conf[0] == param_name:
          param_value = conf[2]
    fd.close()
    return param_value

def param_missing(param_name):
  print "Parameter '"+param_name+"' is missing in the config file (srx.conf)"
  print param_name + ' = <value>'
  exit()

def get_content_srx(login, ip, pw, cmd):
  output = ''
  child = pexpect.spawn ('ssh '+login+'@'+ip+' "'+cmd+'"')
  child.timeout = 90
  child.maxread = 100000
  child.waitnoecho()
  child.sendline(pw+"\n")
  child.expect (pexpect.exceptions.EOF)
  output = output + child.before
  return output



# =======================================================================
# Main section
# =======================================================================


# -----------------------------------------------------------------------
# get all data from SRX (configuration and counters extract from command lines sent to the SRX)
# -----------------------------------------------------------------------

if not PARAM.keypwfile:
  keypwfile = "key_default.enc"
else:
  keypwfile = PARAM.keypwfile

# get the SRX IP address from the config file
# the file's name might be passed and overwrite the config using the option -srx_ip
if PARAM.srx_ip:
  srx_ip = PARAM.srx_ip
else:
  srx_ip = read_conf('srx_ip')

if srx_ip == '':
  param_missing('srx_ip')

srx_login = read_conf('srx_login')
if srx_login == '':
  param_missing('srx_login')


if PARAM.getconf:
  pw=pysec.main(['--dec', '-k', keypwfile])

  # ------------------------------------------
  # get the SRX configuration in XML format
  cmd='show configuration | display xml'
  try:
    srx_conf = get_content_srx(srx_login, srx_ip, pw, cmd)
  except pexpect.exceptions.TIMEOUT:
    print "Timeout", cmd
    exit()

  with open('data/srx_'+srx_ip+'.xml', 'w') as fd:
    # remove the string "Password:" from the output extracted, since pexpect returns this string too.
    # this should be fixed inside the get_content_srx method.
    cmdout = fd.write(srx_conf.replace("Password:",""))
    fd.close()


  # ------------------------------------------
  # get the SRX configuration in straight command line format
  cmd='show configuration | display set'
  try:
    srx_conf_txt = get_content_srx(srx_login, srx_ip, pw, cmd)
  except pexpect.exceptions.TIMEOUT:
    print "Timeout", cmd
    exit()
        
  with open('data/srx_'+srx_ip+'.txt', 'w') as fd:
    # remove the string "Password:" from the output extracted, since pexpect returns this string too.
    # this should be fixed inside the get_content_srx method.
    cmdout = fd.write(srx_conf_txt.replace("Password:",""))
    fd.close()

  # ------------------------------------------
  # get the hit counts of policies
  cmd='show security policies hit-count'
  try:
    hit_counts = get_content_srx(srx_login,srx_ip, pw, cmd)
  except pexpect.exceptions.TIMEOUT:
    print "Timeout", cmd
    exit()

  with open('data/srx_'+srx_ip+'.cnt', 'w') as fd:
    cntout = fd.write(hit_counts)
    fd.close()

  # ------------------------------------------
  # get details information on security policies
  cmd='show security policies'
  try:
    policy_sequences_indexes = get_content_srx(srx_login, srx_ip, pw, cmd)
  except pexpect.exceptions.TIMEOUT:
    print "Timeout", cmd
    exit()

  with open('data/srx_'+srx_ip+'.idx', 'w') as fd:
    cntidx = fd.write(policy_sequences_indexes)
    fd.close()

  # ------------------------------------------
  # get details on NAT Source rules
  cmd='show security nat source rule all'
  try:
    policy_sequences_indexes = get_content_srx(srx_login, srx_ip, pw, cmd)
  except pexpect.exceptions.TIMEOUT:
    print "Timeout", cmd
    exit()

  with open('data/srx-snat_'+srx_ip+'.txt', 'w') as fd:
    cntidx = fd.write(policy_sequences_indexes)
    fd.close()

  # ------------------------------------------
  # get details on NAT Destination rules
  cmd='show security nat destination rule all'
  try:
    policy_sequences_indexes = get_content_srx(srx_login, srx_ip, pw, cmd)
  except pexpect.exceptions.TIMEOUT:
    print "Timeout", cmd
    exit()
        
  with open('data/srx-dnat_'+srx_ip+'.txt', 'w') as fd:
    cntidx = fd.write(policy_sequences_indexes)
    fd.close()


# -----------------------------------------------------------------------
# Read all data generated by the option -getconf (flat text files or CSV files)
# -----------------------------------------------------------------------

try:
  # get read the XML configuration file
  with open('data/srx_'+srx_ip+'.xml') as fd:
    cmdout = fd.read()
  srx = Soup(cmdout, 'xml')

  # get read the TXT counter policies file
  with open('data/srx_'+srx_ip+'.cnt') as fd:
    cntout = fd.read()

  # get read the TXT indexes file
  with open('data/srx_'+srx_ip+'.idx') as fd:
    policy_sequences_indexes = fd.read()

  # get read the TXT counter SNat file
  with open('data/srx-snat_'+srx_ip+'.txt') as fd:
    snat_counters_file = fd.read()

  # get read the TXT counter DNat file
  with open('data/srx-dnat_'+srx_ip+'.txt') as fd:
    dnat_counters_file = fd.read()
except IOError, Except_Argument:
  print Except_Argument
  exit()

# -----------------------------------------------------------------------
# Build a list of Arrays that will be used to generate various script outputs
# -----------------------------------------------------------------------

# ------
policy_counter = {}
for cnt in cntout.split("\n"):
  cnt_line = cnt.split()
  if len(cnt_line)==5:
     policy_counter[cnt_line[3]] = cnt_line[4]

# ------
policy_seq_index = {}
for index in policy_sequences_indexes.split("\n"):
    seq_policy = index.split()
    if len(seq_policy)>0 and seq_policy[0] == "From":
      zone_from = seq_policy[2]
      zone_to = seq_policy[5]
      zone = zone_from+'-'+zone_to
      zone = zone.replace(',','')
      if not policy_seq_index.has_key(zone):
        policy_seq_index[zone] = {}
    if len(seq_policy)==12 and seq_policy[0] == "Policy:":
      policy_name = seq_policy[1]
      policy_name = policy_name.replace(',','')
      if not policy_seq_index[zone].has_key(policy_name):
        policy_seq_index[zone][policy_name] = {}
      policy_seq_index[zone][policy_name]['seq'] = seq_policy[11].replace(',','')
      policy_seq_index[zone][policy_name]['idx'] = seq_policy[5].replace(',','')


# ---------------------------------------------------------------------------------

# get address-book and policies of all zones
top_security = srx.find('security')

# init dictionaries for address-book address-set
address_set_by_name = {}
address_set_by_ip = {}
address_set_by_zone_ip = {}

address_by_name = {}
address_by_ip = {}
address_by_zone_ip = {}

zone_interfaces = {}

# go through all security zones to retreive address-set of address-book
tag_security_zone = scan_tag(top_security.zones, 'security-zone')
for tag_seczone in tag_security_zone:
  for sz in tag_seczone:
    if sz.name == 'name':
      zone = sz.text
    # get address-book for each zone
    if sz.name == 'address-book':
      if not address_set_by_zone_ip.has_key(zone):
        address_set_by_zone_ip[zone] = {}
      if not address_by_zone_ip.has_key(zone):
        address_by_zone_ip[zone] = {}

      tag_address = scan_tag(sz, 'address-set')
      if PARAM.dspwarn:
        print dsp_banner(get_separator('1 - Double reference in Address Book : '+ zone))

      for tag_addbook in tag_address:
        for ab in tag_addbook:
          if ab.name == 'name':
            name = ab.text.strip()
          if ab.name == 'address':
            # FIX: remove CR trail
            ab_text = ab.text.strip()
            if not address_set_by_name.has_key(name):
              address_set_by_name[name] = []
            if not address_set_by_ip.has_key(ab_text):
              address_set_by_ip[ab_text] = []
            if not address_set_by_zone_ip[zone].has_key(ab_text):
              address_set_by_zone_ip[zone][ab_text] = []
            # ----
            if ab_text in address_set_by_name[name]:
              print print_warn('address_set_by_name : double reference : ' + name)
            if name in address_set_by_ip[ab_text]:
              print print_warn('address_set_by_ip : double reference : ' + ab_text)
            if name in address_set_by_zone_ip[zone][ab_text]:
              print print_warn('address_set_by_name : double reference : ' + ab_text)
            # set dictionaries
            address_set_by_name[name].append(ab_text)
            address_set_by_ip[ab_text].append(name)
            address_set_by_zone_ip[zone][ab_text].append(name)

      tag_address = scan_tag(sz, 'address')
      for tag_addbook in tag_address:
        for ab in tag_addbook:
          if ab.name == 'name':
            name = ab.text.strip()
          if ab.name == 'ip-prefix':
            ab_text = ab.text.strip()
            if not address_by_name.has_key(name):
              address_by_name[name] = []
            if not address_by_ip.has_key(ab_text):
              address_by_ip[ab_text] = []
            if not address_by_zone_ip[zone].has_key(ab_text):
              address_by_zone_ip[zone][ab_text] = []

            if ab_text in address_by_name[name]:
              print_warn('address_by_name : double reference : ' + name + ' ' + ab_text)
            if name in address_by_ip[ab_text]:
              print_warn('address_by_ip : double reference : ' + ab_text + ' ' + name)
            if name in address_by_zone_ip[zone][ab_text]:
              print_warn('address_by_zone_ip : double reference : ' + zone + ' ' + ab_text)
            # set dictionaries
            address_by_name[name].append(ab_text)
            address_by_ip[ab_text].append(name)
            address_by_zone_ip[zone][ab_text].append(name)
    if sz.name == 'interfaces':
      name = scan_tag(sz, 'name', 1)
      if zone_interfaces.has_key(zone):
        zone_interfaces[zone].append(name)
      else:
        zone_interfaces[zone] = [name]

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('address-book'))
  print dsp_section('zones -> security_zone -> address-book')
  print dsp_var(' => VAR : address_set_by_name[<address_set>] = [<address>]')
  print '    * address_set : ',len(address_set_by_name)
  print '    * address per address_set : ',dsp_bracket_array(get_bracket_array(address_set_by_name))
  print dsp_var(' => VAR : address_set_by_ip[<address>] = [<address_set>]')
  print '    * address : ',len(address_set_by_name)
  print '    * address_set per address : ',dsp_bracket_array(get_bracket_array(address_set_by_ip))
  print dsp_var(' => VAR : address_set_by_zone_ip[zone][<address>] = [<address_set>]')
  print '    * zone : ',len(address_set_by_zone_ip)
  print '    * address : ',dsp_bracket_array(get_bracket_array(address_set_by_zone_ip))
  for z in address_set_by_zone_ip.keys():
    if len(address_set_by_zone_ip[z])>0:
      print '      - zone:',z,dsp_bracket_array(get_bracket_array(address_set_by_zone_ip[z]))
    else:
      print '      - zone:',z, '(empty)'

if PARAM.array == 'address_set_by_name':
  pp.pprint(address_set_by_name)
elif PARAM.array == 'address_set_by_ip':
  pp.pprint(address_set_by_ip)
elif PARAM.array == 'address_set_by_zone_ip':
  pp.pprint(address_set_by_zone_ip)

if PARAM.array == 'address_by_name':
  pp.pprint(address_by_name)
elif PARAM.array == 'address_by_ip':
  pp.pprint(address_by_ip)
elif PARAM.array == 'address_by_zone_ip':
  pp.pprint(address_by_zone_ip)

# ---------------------------------------------------------------------------------

# init dictionaries for policies
policies = {}
pol_rules = {}

# go through all security zones to retreive address-set of address-book
tag_policies = scan_tag(top_security.policies, 'policy')
for tag_policy in tag_policies:
  for p in tag_policy:
    if p.name == None:
      continue
    if p.name == 'from-zone-name':
      from_zone = p.text
      if not policies.has_key(from_zone):
        policies[from_zone] = {}
      if not policies[from_zone].has_key('policy'):
        policies[from_zone]['policy'] = { }
    if p.name == 'to-zone-name':
      to_zone = p.text
      if policies[from_zone].has_key('scope'):
        if not to_zone in policies[from_zone]['scope']:
          policies[from_zone]['scope'].append(to_zone)
      else:
        policies[from_zone]['scope'] = [to_zone]

      # fill array to build final policy tree graph
      scope = from_zone+'-'+to_zone
      if not pol_rules.has_key(scope):
        pol_rules[scope] = {}

    if p.name == 'policy':
      tag_policy = p.children
      for tag_pol in tag_policy:
        if tag_pol.name == None:
          continue
        if tag_pol.name == 'name':
          policy_name = tag_pol.text.strip()
          if not policies[from_zone]['policy'].has_key(policy_name):
            policies[from_zone]['policy'][policy_name] = {}
          if p.has_attr('inactive'):
            policies[from_zone]['policy'][policy_name]['attr'] = p.attrs
        elif tag_pol.name == 'match':
          for pol in tag_pol.children:
            if pol.name == None:
              continue
            pol_field = pol.name.strip()
            pol_text = pol.text.strip()
            #handle 'source-address' & 'destination-address' & 'application'
            try:
              policies[from_zone]['policy'][policy_name][pol_field].append(pol_text)
            except KeyError:
              policies[from_zone]['policy'][policy_name][pol_field] = [ pol_text ]

        elif tag_pol.name == 'then':
          # add for each rule the field 'scope' to avoid to
          # rebuild it from policy_name later
          # (which has apparently the format 'from-to-description')
          if not policies[from_zone]['policy'][policy_name].has_key('scope'):
            policies[from_zone]['policy'][policy_name]['scope'] = scope

          for pol in tag_pol.children:
            if pol.name == None:
              continue
            pol_field = pol.name.strip()
            #handle 'permit', 'log', 'reject' & 'count'
            try:
              policies[from_zone]['policy'][policy_name]['then'].append(pol_field)
            except KeyError:
              policies[from_zone]['policy'][policy_name]['then'] = [ pol_field ]

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('policies'))
  print dsp_section('security -> policies')
  
  print dsp_var(' => VAR : policies[<from-zone>][\'policy\'][<policy-name>][<application>] = [list of port]')
  for z in policies.keys():
    if len(policies[z])>0:
      print '      - zone:',z,dsp_bracket_array(get_bracket_array(policies[z]['policy'], 'application'))

  print dsp_var(' => VAR : policies[<from-zone>][\'policy\'][<policy-name>][<source-address>] = [<address>]')
  for z in policies.keys():
    if len(policies[z])>0:
      print '      - zone:',z,dsp_bracket_array(get_bracket_array(policies[z]['policy'], 'source-address'))

  print dsp_var(' => VAR : policies[<from-zone>][\'policy\'][<policy-name>][<destination-address>] = [<address>]')
  for z in policies.keys():
    if len(policies[z])>0:
      print '      - zone:',z,dsp_bracket_array(get_bracket_array(policies[z]['policy'], 'destination-address'))

  print dsp_var(' => VAR : policies[<from-zone>][\'policy\'][<policy-name>][\'then\'] = [\'permit\', \'log\', \'count\']')
  print dsp_var(' => VAR : policies[<from-zone>][<scope>] = [<zone-to>]')

if PARAM.array == 'policies':
  pp.pprint(policies)

# ---------------------------------------------------------------------------------
# NAT SOURCE
# ---------------------------------------------------------------------------------

# ------
# parsing SNAT counters is a bit tricky
# each time the parser sees "source NAT rule:", the NAT's name is then caugth
# then the parser get all parameter assiciate to this NAT's name until it sees
# a new line with "source NAT rule:"

arr_snat_counters = {}
max_item_kv_snat = {} # needed to know later the number of columns used in the output
nat_name_defined = 0

for line_snat_counter in snat_counters_file.split("\n"):
  kv_snat_counter = [k.strip() for k in line_snat_counter.split(':')]
  if line_snat_counter.startswith('source NAT rule:'):
    nat_name = kv_snat_counter[1].replace(' Rule-set','').strip()
    # since there might be several nodes, thus several times a set of parameters
    # with differents values for the same parameters, the array is initialized only
    # if this does not already exist.
    if not arr_snat_counters.has_key(nat_name):
      arr_snat_counters[nat_name] = {}
  else:
    # continue if the variable nat_name is not yet defined.
    # this means the string "source NAT rule:" has not been seen yet.
    # the flag nat_name_defined exists to avoid looking for inside locals() for each loop
    if not nat_name_defined and 'nat_name' in locals():
      nat_name_defined = 1
    if not nat_name_defined:
      continue

    try:
      # catch parameter for a given NAT's name only this the split of the line contains 2 elements
      if len(kv_snat_counter) != 2 or kv_snat_counter[0] == '':
        continue
      # get parameter's value first for the note0, then append the value for the other nodes if any
      if arr_snat_counters[nat_name].has_key(kv_snat_counter[0]):
        arr_snat_counters[nat_name][kv_snat_counter[0]].append(kv_snat_counter[1])
      else:
        arr_snat_counters[nat_name][kv_snat_counter[0]] = [kv_snat_counter[1]]
    except:
      pass
    # collect the maximum numbers of items for a given parameter across all NAT's name.
    # this is usefull to know the number of columns to display during the output process
    if not max_item_kv_snat.has_key(kv_snat_counter[0]):
      max_item_kv_snat[kv_snat_counter[0]] = 1
    if max_item_kv_snat[kv_snat_counter[0]] < len(arr_snat_counters[nat_name][kv_snat_counter[0]]):
      max_item_kv_snat[kv_snat_counter[0]] = len(arr_snat_counters[nat_name][kv_snat_counter[0]])

# end of the NAT counter parser


# init dictionaries for NATs
nat_source_pool_ip = {}
nat_source_pool_name = {}
nat_source_rule_set = {}
nat_source_rule_name = {}

# go through all security zones to retreive NAT source
tag_nat = scan_tag(top_security.nat, 'source')
for nat_source in tag_nat:
  for source in nat_source:
    if source.name == None:
      continue
    # mapping of name => ip & ip => name
    if source.name == 'pool':
      for src in source.children:
        if src == None or src.name==None:
          continue
        elif src.name == 'name':
          pool_name = src.text
        elif src.name == 'address':
          nat_ip = scan_tag(src, 'name', 1)
          nat_ip_to = ''
          try:
            nat_ip_to = scan_tag(src.to, 'ipaddr', 1)
            if nat_ip != nat_ip_to:
              nat_ip = nat_ip+'*'+nat_ip_to
          except AttributeError:
            pass
          try:
            nat_source_pool_ip[pool_name].append(nat_ip)
          except:
            nat_source_pool_ip[pool_name] = [nat_ip]
          try:
            nat_source_pool_name[nat_ip].append(pool_name)
          except:
            nat_source_pool_name[nat_ip] = [pool_name]
    elif source.name == 'rule-set':
      rule_set_name = ''
      zone_from_name = ''
      zone_to_name = ''
      rule_name = ''
      for src in source.children:
        if src == None or src.name==None:
          continue
        elif src.name == 'name':
            rule_set_name = src.text
        elif src.name == 'from':
          zone_from_name = scan_tag(src, 'zone', 1)
        elif src.name == 'to':
          zone_to_name = scan_tag(src, 'zone', 1)
        elif src.name == 'rule':
          rule_name = scan_tag(src, 'name', 1)
          source_address = []
          destination_address = []
          for rules in src.children:
            if rules == None:
              continue
            for rule in rules:
              if rule == None or type(rule) is unicode or rule.name == None:
                continue
              if rule.name.strip() == 'source-address':
                if rule.text.strip() not in source_address:
                  source_address.append(rule.text.strip())
              if rule.name.strip() == 'destination-address':
                if rule.text.strip() not in destination_address:
                  destination_address.append(rule.text.strip())
              if rule.name.strip() == 'source-nat':
                for pools in rule:
                  for pool in pools:
                    if pool == None or type(pool) is unicode or pool.name == None:
                      continue
                    pool_nat = pool.text

          for src in source_address:
            if not nat_source_rule_name.has_key(src):
              nat_source_rule_name[src] = [[rule_set_name, zone_from_name, zone_to_name, rule_name, pool_nat, nat_source_pool_ip[pool_nat], destination_address]]
            if pool_nat not in (pnat[4] for pnat in nat_source_rule_name[src]):
              nat_source_rule_name[src].append([rule_set_name, zone_from_name, zone_to_name, rule_name, pool_nat, nat_source_pool_ip[pool_nat], destination_address])

        if zone_from_name == '' or zone_to_name == '' or rule_name == '':
           continue
        if not nat_source_rule_set.has_key(zone_from_name):
          nat_source_rule_set[zone_from_name] = {}
        if not nat_source_rule_set[zone_from_name].has_key(zone_to_name):
          nat_source_rule_set[zone_from_name][zone_to_name] = []
        nat_source_rule_set[zone_from_name][zone_to_name].append(rule_name)
          

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('NAT source'))
  print dsp_section('security -> nat -> source -> pool')
  print dsp_var(' => VAR : nat_source_pool_ip[<pool-name>] = [<address>]')
  print '    * pool_name : ',len(nat_source_pool_ip)
  print '    * address per pool_name : ',dsp_bracket_array(get_bracket_array(nat_source_pool_ip))
  print dsp_var(' => VAR : nat_source_pool_name[<address>] = [<pool-name>]')
  print '    * address : ',len(nat_source_pool_name)
  print '    * pool_name per address : ',dsp_bracket_array(get_bracket_array(nat_source_pool_name))
  print dsp_section('security -> nat -> source -> rule-set')
  
  print dsp_var(' => VAR : nat_source_rule_set[<from-zone>][<to-zone>] = [<rule_name>]')
  print '    * from-zone : ',len(nat_source_rule_set)
  for z in nat_source_rule_set.keys():
    if len(nat_source_rule_set[z])>0:
      print '      - zone:',z,dsp_bracket_array(get_bracket_array(nat_source_rule_set[z]))

  print dsp_var(' => VAR : nat_source_rule_name[<source-address>] = [<rule_name>, <pool-nat>, <address>, <destination>]')
  print '    * len(nat_source_rule_name) : ',len(nat_source_rule_name)
  print '    * snat_source-address : ',len(source_address)
  print '    * snat_destination-address : ',len(destination_address)

if PARAM.array == 'nat_source_pool_ip':
  pp.pprint(nat_source_pool_ip)
elif PARAM.array == 'nat_source_pool_name':
  pp.pprint(nat_source_pool_name)
elif PARAM.array == 'nat_source_rule_set':
  pp.pprint(nat_source_rule_set)
elif PARAM.array == 'nat_source_rule_name':
  pp.pprint(nat_source_rule_name)
elif PARAM.array == 'snat_source_address':
  pp.pprint(source_address)
elif PARAM.array == 'snat_destination_address':
  pp.pprint(destination_address)


# ---------------------------------------------------------------------------------
# NAT DESTINATION
# ---------------------------------------------------------------------------------

# init dictionaries for NATs
nat_destination_pool_ip = {}
nat_destination_pool_name = {}
nat_destination_rule_set = {}
nat_destination_rule_name = {}

# go through all security zones to retreive NAT destination
tag_nat = scan_tag(top_security.nat, 'destination')
for nat_destination in tag_nat:
  for dest in nat_destination:
    if dest.name == None:
      continue
    # mapping of name => ip & ip => name
    if dest.name == 'pool':
      for destination in dest.children:
        if destination == None or destination.name==None:
          continue
        elif destination.name == 'name':
          pool_name = destination.text
        elif destination.name == 'address':
          nat_ip = destination.text.strip()
          try:
            nat_ip = scan_tag(destination, 'ipaddr', 1)
          except AttributeError:
            nat_ip = ''
          try:
            nat_destination_pool_ip[pool_name].append(nat_ip)
          except:
            nat_destination_pool_ip[pool_name] = [nat_ip]
          try:
            nat_destination_pool_name[nat_ip].append(pool_name)
          except:
            nat_destination_pool_name[nat_ip] = [pool_name]
    elif dest.name == 'rule-set':
      rule_set_name = ''
      zone_from_name = ''
      rule_name = ''
      for destination in dest.children:
        if destination == None or destination.name==None:
          continue
        elif destination.name == 'name':
          rule_set_name = destination.text
        elif destination.name == 'from':
          zone_from_name = scan_tag(destination, 'zone', 1)
        elif destination.name == 'rule':
          rule_name = scan_tag(destination, 'name', 1)

          source_address = []
          destination_address = []
          for rules in destination.children:
            if rules == None:
              continue
            for rule in rules:
              if rule == None or type(rule) is unicode or rule.name == None:
                continue
              if rule.name.strip() == 'source-address':
                if rule.text.strip() not in source_address:
                  source_address.append(rule.text.strip())
              if rule.name.strip() == 'destination-address':
                if rule.text.strip() not in destination_address:
                  destination_address.append(rule.text.strip())
              if rule.name.strip() == 'destination-nat':
                for pools in rule:
                  for pool in pools:
                    if pool == None or type(pool) is unicode or pool.name == None:
                      continue
                    pool_nat = pool.text

          for dest in destination_address:
            if not nat_destination_rule_name.has_key(dest):
              nat_destination_rule_name[dest] = [[rule_set_name, zone_from_name, rule_name, source_address, pool_nat, nat_destination_pool_ip[pool_nat][0]]]
            if pool_nat not in (pnat[4] for pnat in nat_destination_rule_name[dest]):
              nat_destination_rule_name[dest].append([rule_set_name, zone_from_name, rule_name, source_address, pool_nat, nat_destination_pool_ip[pool_nat][0]])


        if zone_from_name == '' or rule_name == '':
          continue

        if not nat_destination_rule_set.has_key(zone_from_name):
          nat_destination_rule_set[zone_from_name] = []
        nat_destination_rule_set[zone_from_name].append(rule_name)

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('NAT destination'))
  print dsp_section('security -> nat -> destination -> pool')
  print dsp_var(' => VAR : nat_destination_pool_ip[<pool-name>] = [<address>]')
  print '    * pool_name : ',len(nat_destination_pool_ip)
  print '    * address per pool_name : ',dsp_bracket_array(get_bracket_array(nat_destination_pool_ip))
  print dsp_var(' => VAR : nat_destination_pool_name[<address>] = [<pool-name>]')
  print '    * address : ',len(nat_destination_pool_name)
  print '    * pool_name per address : ',dsp_bracket_array(get_bracket_array(nat_destination_pool_name))
  print dsp_section('security -> nat -> destination -> rule-set')
  
  print dsp_var(' => VAR : nat_destination_rule_set[<from-zone>][<to-zone>] = [<rule_name>]')
  print '    * from-zone : ',len(nat_destination_rule_set)
  for z in nat_destination_rule_set.keys():
    if len(nat_destination_rule_set[z])>0:
      print '      - zone:',z,dsp_bracket_array(get_bracket_array(nat_destination_rule_set))

  print dsp_var(' => VAR : nat_destination_rule_name[<destination-address>] = [<rule_name>, <pool-nat>, <address>, <source>]')
  print '    * len(nat_destination_rule_name) : ',len(nat_destination_rule_name)
  print '    * dnat_source_address : ',len(source_address)
  print '    * dnat_destination_address : ',len(destination_address)

if PARAM.array == 'nat_destination_pool_ip':
  pp.pprint(nat_destination_pool_ip)
elif PARAM.array == 'nat_destination_pool_name':
  pp.pprint(nat_destination_pool_name)
elif PARAM.array == 'nat_destination_rule_set':
  pp.pprint(nat_destination_rule_set)
elif PARAM.array == 'nat_destination_rule_name':
  pp.pprint(nat_destination_rule_name)
elif PARAM.array == 'dnat_source_address':
  pp.pprint(source_address)
elif PARAM.array == 'dnat_destination_address':
  pp.pprint(destination_address)

# ---------------------------------------------------------------------------------

# get applications (ports)
applications = srx.find('applications')
ports = {}
protocols = {}
ports_name = {}

if PARAM.dspwarn:
  print dsp_banner(get_separator('2 - Applications appearing more than once'))

# go through all security zones to retreive address-set of address-book
tag_application = scan_tag(applications, 'application')
for tag_app in tag_application:
  for app in tag_app:
    if app.name == None:
      continue
    else:
      if app.name == 'name':
        name = app.text
      elif app.name == 'protocol':
        protocol = app.text
        protocols[protocol] = 1
        if not ports.has_key(protocol):
          ports[protocol] = {}
        if not ports_name.has_key(protocol):
          ports_name[protocol] = {}
      elif app.name == 'destination-port':
        port = app.text.replace('-', ':')
        # replace '-' by ':' to use a diffent separator than in policy name
        if not ports[protocol].has_key(name):
          ports[protocol][name] = port
        else:
          print_warn('port "'+name+'" / "'+protocol+'" appears more than once')
        
        if not ports_name[protocol].has_key(port):
          ports_name[protocol][port] = [name]
        else:
          ports_name[protocol][port].append(name)

if PARAM.dspwarn:
  for protocol in protocols.keys():
    for p in ports_name[protocol]:
      if len(ports_name[protocol][p])>1:
        print_warn('double port ' + p + ' ' + repr(ports_name[protocol][p]))

# go through all security zones to retreive address-set of address-book
tag_application_set = scan_tag(applications, 'application-set')
ports_set = {}

for tag_app in tag_application_set:
  for app in tag_app:
    if app.name == None:
      continue
    else:
       if app.name == 'name':
         name = app.text
       if app.name == 'application':
         try:
           ports_set[name].append(app.text.strip())
         except:
           ports_set[name] = [app.text.strip()]

def get_port(port):
  """ returns the port number whatever the application
  or application-set provided"""
  global ports
  global ports_set
  global protocols
  for protocol in protocols:
    if port in ports[protocol].keys():
      return [ports[protocol][port]]
    elif port in ports_set.keys():
      p_set = []
      for p in ports_set[port]:
        try:
          p_set.append(ports[protocol][p])
        except:
          if ports.has_key(protocol) and ports[protocol].has_key(p):
            p_set = [ports[protocol][p]]
      if len(p_set)>0:
        return p_set
    else:
      return [port]

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('Applications (ports)'))
  print dsp_section('applications -> application')
  print dsp_var(' => VAR : ports[<protocol>][<application>] = [<port>]')
  print '    * application : ',len(ports)
  for p in ports.keys():
    if len(ports[p])>0:
      print '      - protocol:',p,dsp_bracket_array(get_bracket_array(ports[p]))
    else:
      print '      - protocol:',p

  print dsp_section('applications -> application-set')
  print dsp_var(' => VAR : ports_set[<name>] = [<application>]')
  print '    * application-set : ',len(ports_set)

if PARAM.array == 'ports':
  pp.pprint(ports)
if PARAM.array == 'ports_set':
  pp.pprint(ports_set)

# ---------------------------------------------------------------------------------

# reslice the policies_rules array in order to display graphviz graph
# this must stay after 'ports' section in order to user this variable
for zone in policies.keys():
  for pol in policies[zone]['policy'].keys():
    p = policies[zone]['policy'][pol]
    for port in p['application']:
      if 'permit' in p['then']:
        access = 'permit'
      elif 'deny' in p['then']:
        access = 'deny'
      elif 'reject' in p['then']:
        access = 'reject'
      else:
        access = 'NA'

      if not pol_rules[p['scope']].has_key(access):
        pol_rules[p['scope']][access] = {}

      for getport in get_port(port):
        source = p['source-address']
        dest = p['destination-address']
        try:
          pol_rules[p['scope']][access][getport].append([source, dest, pol])
        except:
          pol_rules[p['scope']][access][getport] = [[source, dest, pol]]

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('Policies Rules'))
  print dsp_section('security -> policies')
  print dsp_var(' => VAR : pol_rules[<scope>][<access>][<port>] = [[[<source>], [<dest>], polname]]')
  print '    * scope : ',len(pol_rules.keys())
  for s in pol_rules.keys():
    if len(pol_rules[s])>0:
      print '      - access :',s,repr(pol_rules[s].keys()),dsp_bracket_array(get_bracket_array(pol_rules[s]))
  print dsp_var(' => VAR : pol_rules_not_permit : display list of ports for <deny> and <reject>')

if PARAM.array == 'pol_rules':
  pp.pprint(pol_rules)
if PARAM.array == 'pol_rules_not_permit':
  for s in pol_rules.keys():
    for a in pol_rules[s].keys():
      if a is not 'permit':
        print s, a
        pp.pprint(pol_rules[s][a])

# Build a counter to detect the addresses
# used in address-book of different zones
count_ip_in_zone={}
for zone in address_by_zone_ip.keys():
  for ip in address_by_ip.keys():
    if address_by_zone_ip[zone].has_key(ip):
      if count_ip_in_zone.has_key(ip):
        count_ip_in_zone[ip].append(zone)
      else:
        count_ip_in_zone[ip] = [zone]

# ---------------------------------------------------------------------------------

# get interfaces
# each zone are defined by a list of interfaces
top_interfaces = srx.find('configuration')
interfaces = {}

tag_interfaces = scan_tag(top_interfaces, 'interfaces')

for interfs in tag_interfaces:
  for ifs in interfs:
    if ifs == None:
      continue
    elif ifs.name == 'interface':
      for tag_interface in ifs.children:
        if tag_interface.name == None:
          continue
        else:
          if tag_interface.name == 'name':
            name = tag_interface.text
            vlan_tagging = 0
          elif tag_interface.name == 'gigether-options':
            parent = scan_tag(tag_interface, 'redundant-parent')
            for par_ifs in parent:
              for parent in par_ifs:
                if parent.name == 'parent':
                  if interfaces.has_key(parent.text) and interfaces[parent.text].has_key('port'):
                    interfaces[parent.text]['port'].append(name)
                  else:
                    interfaces[parent.text] = { 'port' : [name] }
          elif tag_interface.name == 'fabric-options':
            fabric_options = scan_tag(tag_interface, 'member-interfaces')
            for fab_opts in fabric_options:
              for fab in fab_opts:
                if fab.name == 'name':
                  if interfaces.has_key(fab.text) and interfaces[fab.text].has_key('port'):
                    interfaces[fab.text]['port'].append(name)
                  else:
                    interfaces[name] = { 'port' : [fab.text] }
          elif tag_interface.name == 'vlan-tagging':
            vlan_tagging = 1
          elif tag_interface.name == 'unit':
            unit_name = scan_tag(tag_interface, 'name', 1)
            unit_desc = scan_tag(tag_interface, 'description', 1)
            if vlan_tagging == 1:
              unit_vlan_id = scan_tag(tag_interface, 'vlan-id', 1)
            else:
              unit_vlan_id = "None"
            unit_family = scan_tag(tag_interface, 'family')
            for family in unit_family:
              for inet in family:
                if inet.name == None:
                  continue
                elif inet.name == "inet":
                  ip_list = []
                  ip_preferred = ''
                  for add in inet.children:
                    if add.name == None:
                      continue
                    elif add.name == 'address':
                      ip = add.text.strip()
                      for pref in add.children:
                        if pref == None:
                          continue
                        if pref.name == 'preferred':
                          ip_preferred = ip
                      ip_list.append(ip)
            
            interfaces[name+'.'+unit_name] = {
              'ip_prefered' : ip_preferred,
              'desc' : unit_desc,
              'vlan' : unit_vlan_id,
              'ip' : ip_list
            }

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('Interfaces'))
  print dsp_section('interfaces -> interface')
  print dsp_var(" => VAR : interfaces[<name>] = { 'ip_prefered':<ip>, 'desc':<unit_desc>, 'vlan':<vlan>, 'ip':[<ips>] }")
  print '    * interfaces : ',len(interfaces.keys())
  print dsp_var(" => VAR : interfaces_list : list of interfaces")

if PARAM.array == 'interfaces_list':
  for i in interfaces.keys():
    try:
      print ' - if :',col_purple(i), interfaces[i]['ip'], col_blue(interfaces[i]['vlan'])
    except:
      print


if PARAM.array == 'interfaces':
  pp.pprint(interfaces)

# ---------------------------------------------------------------------------------

# get interfaces
# each zone are defined by a list of interfaces
top_route = srx.find('configuration')
static_routes = {}
sr = netaddr.IPSet()

top_routing = scan_tag(top_route, 'routing-options')

if PARAM.dspwarn:
  print dsp_banner(get_separator('3 - Static Route : load balancing ?'))

for routing in top_routing:
  for r_static in routing:
    if r_static == None or r_static.name == None:
      continue
    if r_static.name == 'static':
      for route in r_static.children:
        for r in route:
          if r == None or type(r) is unicode or r.name == None:
            continue
          if r.name == 'name':
            name = r.text
            if static_routes.has_key(name):
              print_warn('static_route "'+name+'" appears more than once')
            static_routes[name] = []
          elif r.name == 'next-hop':
            static_routes[name].append(r.text)
            if not name == '0.0.0.0/0':
              sr.add(name)

# -----------------
# STAT
# -----------------
if PARAM.dspstat:
  print dsp_banner(get_separator('Routing Options'))
  print dsp_section('routing-options')
  print dsp_var(' => VAR : static_routes[<name>] = [<address>]')
  print '    * route : ',len(static_routes.keys())
  print '      - route :',dsp_bracket_array(get_bracket_array(static_routes))

if PARAM.array == 'static_routes':
  pp.pprint(static_routes)




# =======================================================================
# Script OUTPUT
# =======================================================================

# Display the output depending of all options passed to the script


# -----------------------------------------------------------------------
# list IP duplicated accross zones
if PARAM.dspwarn:
  print dsp_banner(get_separator('4 - list of duplicated IP accross zones'))
  for ip in count_ip_in_zone.keys():
    if len(count_ip_in_zone[ip])>1:
      print_warn(ip+' count : '+str(len(count_ip_in_zone[ip]))+' : '+repr(count_ip_in_zone[ip]))

# -----------------------------------------------------------------------
# list all zones and the number of address in their address-book
if PARAM.lzone:
  for zone in address_by_zone_ip.keys():
    # display the number of address in each zone
    print zone, len(address_by_zone_ip[zone])

# -----------------------------------------------------------------------
# list all zones and the number of address-set in their address-book
if PARAM.laddrset:
  for zone in address_set_by_zone_ip.keys():
    # display the number of address in each zone
    print zone, len(address_set_by_zone_ip[zone])

# -----------------------------------------------------------------------
# list all IP in a given zone
if PARAM.zoneip and not PARAM.oneline:
  # depending on the 'allip' parameter, zone_ip will be
  # either all zones or the one provided
  if PARAM.allip:
    zone_ip = address_by_zone_ip.keys()
  else:
    zone_ip = [PARAM.zoneip]
  for z in zone_ip:
    try:
      for ip in address_by_zone_ip[z]:
        print ip, address_by_zone_ip[z][ip],
        # append to the previous line (ended by a comma)
        # the zone if 'allip' parameter is provided
        if PARAM.allip:
          print z
        else:
          print ''
    except:
      print "Zone '"+z+"' does not exist"

# -----------------------------------------------------------------------
# list all IP in a given zone
if PARAM.zoneaddrset:
  try:
    for ip in address_set_by_zone_ip[PARAM.zoneaddrset]:
      print ip, address_set_by_zone_ip[PARAM.zoneaddrset][ip]
  except:
    print "Zone '"+PARAM.zoneaddrset+"' does not exist"

# -----------------------------------------------------------------------
# list all uniq IP (accross all zones)
if PARAM.allip and not PARAM.zoneip:
  for ip in address_by_ip:
    index = 0
    for i in address_by_ip[ip]:
      index += 1
      print index, ip, i

# -----------------------------------------------------------------------
# list all policies, one per line (accross all zones or one specific zone)
if PARAM.oneline:
  separator = "\t"
  # print field name on first line
  if not PARAM.noheader:
    print "nom"+separator+"src"+separator+"port"+separator+"dest"+separator+"count"+separator+"zones"+separator+"action"+separator+"active"+separator+"index"+separator+"sequences"
  for zone in policies.keys():
    # in order to specify only one zone to look for policies
    if PARAM.zoneip and policies.has_key(PARAM.zoneip) and zone != PARAM.zoneip:
      continue
  
    for policy_name in policies[zone]['policy']:
      print policy_name,
      app = []
      src_name = []
      dest_name = []

      for application in policies[zone]['policy'][policy_name]['application']:
        app.append(application)
      for source_name in policies[zone]['policy'][policy_name]['source-address']:
          src_name.append(source_name)
      for destination_name in policies[zone]['policy'][policy_name]['destination-address']:
          dest_name.append(destination_name)
      # catch exception when policity counter is not available
      try:
        line = separator, ','.join(src_name), \
            separator, '[',','.join(app),']', \
            separator, ','.join(dest_name), \
            separator, policy_counter[policy_name]
      except:
          line = separator, ','.join(src_name), \
            separator, '[',','.join(app),']', \
            separator, ','.join(dest_name), \
            separator, "N/A"
      # check if the policy has an inactive attribute
      try:
        attr = policies[zone]['policy'][policy_name]['attr']['inactive']
      except:
        attr = 'active'

      try:
        idx = policy_seq_index[policies[zone]['policy'][policy_name]['scope']][policy_name]['idx']
        seq = policy_seq_index[policies[zone]['policy'][policy_name]['scope']][policy_name]['seq']
      except:
        idx = "N/A"
        seq = "N/A"


      print ' '.join(line), \
          separator, policies[zone]['policy'][policy_name]['scope'], \
          separator, policies[zone]['policy'][policy_name]['then'], \
          separator, attr, \
          separator, idx, \
          separator, seq

# -----------------------------------------------------------------------
# list all uniq address-set (accross all zones)
if PARAM.alladdrset:
  for ip in address_set_by_ip:
    index = 0
    for i in address_set_by_ip[ip]:
      index += 1
      print index, i, ip

# -----------------------------------------------------------------------
# list all zones for each policies (and display Interfaces attached to each zone)
if PARAM.zpolicies:
  doublon = {}
  if PARAM.graphviz:
    print graphviz_header()
  for from_zone in policies:
    for to_zone in policies[from_zone]['scope']:
      if PARAM.graphviz:
        try:
          for s_zone in zone_interfaces[from_zone]:
            key = interfaces[s_zone]['ip'][0] + '\nVlan: ' + interfaces[s_zone]['vlan'] # + '\n' + interfaces[s_zone]['desc']
            if not doublon.has_key(key):
              print '"' + from_zone + '" -> "' + s_zone + ' (' + key + ')' + '";'
            doublon[key] = 1
          for d_zone in zone_interfaces[to_zone]:
            key = interfaces[d_zone]['ip'][0] + '\nVlan: ' + interfaces[d_zone]['vlan'] # + '\n' + interfaces[d_zone]['desc']
            if not doublon.has_key(key):
              print '"' + to_zone + '" -> "' + d_zone + ' (' + key + ')' + '";'
            doublon[key] = 1
        except IndexError:
          pass
        print '"' + from_zone + '" [shape=circle];'
        print '"' + to_zone + '" [shape=circle];'
        print '"' + from_zone + '" -> "' + to_zone + '";'
      else:
        print from_zone, '=>', to_zone
  if PARAM.graphviz:
    print graphviz_footer()

# -----------------------------------------------------------------------
if PARAM.dspwarn:
  print dsp_banner(get_separator('5 - list IP used in 2 different address book'))
  for ip in address_by_ip:
    if len(address_by_ip[ip])>1:
      for i in address_by_ip[ip]:
        print_warn(ip+' => '+i)

  print dsp_banner(get_separator('6 - list of address book used in '))
  for name in address_by_name:
    if len(address_by_name[name])>1:
      for n in address_by_name[name]:
        print_warn(name+' => '+n)



# -----------------------------------------------------------------------
if PARAM.rulescomb:
  zones_list = {}
  if PARAM.onlyfrom:
    for comb in pol_rules.keys():
      zones_list[comb.split('-')[0]] = 1
    for z in zones_list.keys():
      print z
  elif PARAM.onlyto:
    for comb in pol_rules.keys():
      zones_list[comb.split('-')[1]] = 1
    for z in zones_list.keys():
      print z
  else:
    for comb in pol_rules.keys():
      print comb

# -----------------------------------------------------------------------
if PARAM.rulestree:
  zone_scan = pol_rules.keys()
  print graphviz_header()
  if PARAM.rulestree in zone_scan:
    for zone in [PARAM.rulestree]:
      if pol_rules[zone].has_key('permit'):
        for port in pol_rules[zone]['permit']:
          if PARAM.port and not port == PARAM.port:
            continue
          source = pol_rules[zone]['permit'][port][0][0]
          dest = pol_rules[zone]['permit'][port][0][1]
          rule_name = pol_rules[zone]['permit'][port][0][2]
          rule_name = rule_name.replace(zone+'-', "")
          print '"' + port + '" [width=2 shape=circle style=filled fillcolor=grey];'
          for s in source:
            _s = 'S:'+rule_name + '\n' + s
            print '"' + _s + '" [width=5 shape=rect style=filled fillcolor=green];'
          for d in dest:
            _d = d + '\nD:' + rule_name
            print '"' + _d + '" [width=5 shape=rect style=filled fillcolor=red];'

          for s in source:
            _s = 'S:'+rule_name + '\n' + s
            print '"' + _s + '" -> "' + port + '";'
          for d in dest:
            _d = d + '\nD:' + rule_name
            print '"' + port + '" -> "' + _d + '";'

  print graphviz_footer()

# -----------------------------------------------------------------------
if PARAM.mergeall:
  # source de la base de l'algo
  # http://stackoverflow.com/questions/30227466/combine-several-images-horizontally-with-python
  # http://stackoverflow.com/questions/16373425/add-text-on-image-using-pil
  # http://stackoverflow.com/questions/2726171/how-to-change-font-size-using-the-python-imagedraw-library
  
  # get all images in the graphs directory (for the moment, this directory is hard coded)
  list_images = []
  for comb in pol_rules.keys():
    list_images.append(PARAM.mergeall+'/'+comb+'.jpg')
  images = map(Image.open, list_images)
  # build a piece of image to overlap the image by the image's name
  draw = map(ImageDraw.Draw, images)

  # TOFIX: hard code the font file otherwise not found
  fontpath = "./arial.ttf"
  font = ImageFont.truetype(fontpath, 32)
  index = 0

  # go through each image to add the image's name and a border.
  for comb in pol_rules.keys():
    draw[index].text((10, 10),comb,(0,0,255),font=font)
    images[index] = ImageOps.expand(images[index], border=5, fill='black')
    index += 1

  # pack in a list of tuple the width and heights of each image
  widths, heights = zip(*(i.size for i in images))

  # align verticaly the images and locally push the next image on the same line
  # when space is big enough to align the next image on the same horizontal line.

  # init coordinates variables
  max_width = max(widths)
  max_height = max(heights)
  pos_x = [0]
  pos_y = [0]
  curr_width = widths[0]
  jump_line = 0

  for count_im in range(1,len(widths)):
    # align the image horizontaly
    if curr_width + widths[count_im] <= max_width:
      pos_x.append(curr_width)
      curr_width += widths[count_im]
    # otherwise start aligning the image on the following line
    else:
      pos_x.append(0)
      curr_width = widths[count_im]
      jump_line += 1
    pos_y.append(max_height * jump_line)

  jump_line += 1
  total_height = max_height * jump_line

  # create a big image to insert all the images
  new_im = Image.new('RGB', (max_width, total_height), 'White')
  counter = 0
  for im in images:
    new_im.paste(im, (pos_x[counter], pos_y[counter]))
    counter += 1

  new_im.save('graphs/ALL.jpg')

# -----------------------------------------------------------------------
if PARAM.graphroute:
  print graphviz_header()
  for r in static_routes:
    for s in sr.iter_cidrs():
      s1 = netaddr.IPSet([s])
      if r in s1:
        print '"'+r+ '" -> "' +repr(s).split("'")[1]+'";'
  print graphviz_footer()


# -----------------------------------------------------------------------
if PARAM.ipaddrbook:
  for addr in get_ips_from_address_book(PARAM.ipaddrbook):
    print addr


# -----------------------------------------------------------------------
if PARAM.lsnat:
  separator = "\t"
  pass_flag = 0

  for saddr in nat_source_rule_name:
    zone_from = nat_source_rule_name[saddr][0][1]
    zone_to = nat_source_rule_name[saddr][0][2]
    nat_rule_name = nat_source_rule_name[saddr][0][3]
    nat_pool_name = nat_source_rule_name[saddr][0][4]
    nat_pool_ip = nat_source_rule_name[saddr][0][5]
    nat_pool_dest = nat_source_rule_name[saddr][0][6]
    
    if PARAM.ldnat:
      dest_match_header = separator+"pool_dest_name"+separator+"pool_dest_ip"
      try:
        dest_nat = nat_destination_rule_name[nat_pool_ip[0]]
        dest_match = separator + dest_nat[0][4] + \
          separator + dest_nat[0][5]
      except:
        dest_match = ''
    else:
      dest_match = ''
      dest_match_header = ''

    # print field name on first line
    if not PARAM.noheader and not pass_flag:
      print "zone_from"+separator+"zone_to"+separator+"rule_name"+separator+"ip_before_snat"+separator+"subnet"+separator+"ip_dest"+separator+"pool_name"+separator+"pool_ip"+separator + \
            separator.join(["translation_hits"+str(i) for i in range(max_item_kv_snat['Translation hits'])]) + separator + \
            separator.join(["rule_position"+str(i) for i in range(max_item_kv_snat['Rule position'])]) + separator + \
            separator.join(["failed_session"+str(i) for i in range(max_item_kv_snat['Failed sessions'])]) + separator + \
            separator.join(["successful_session"+str(i) for i in range(max_item_kv_snat['Successful sessions'])]) + separator + \
            dest_match_header
      pass_flag = 1

    try:
      translation_hits = separator.join(arr_snat_counters[nat_rule_name]['Translation hits'])
    except:
      translation_hits = ''
    try:
      rule_position = separator.join(arr_snat_counters[nat_rule_name]['Rule position'])
    except:
      rule_position = ''
    try:
      failed_session = separator.join(arr_snat_counters[nat_rule_name]['Failed sessions'])
    except:
      failed_session = ''
    try:
      successful_session = separator.join(arr_snat_counters[nat_rule_name]['Successful sessions'])
    except:
      successful_session = ''

    print zone_from + \
          separator + zone_to + \
          separator + nat_rule_name + \
          separator + saddr + \
          separator + saddr.split('/')[1] + \
          separator + ','.join(nat_pool_dest) + \
          separator + nat_pool_name + \
          separator + ','.join(nat_pool_ip) + \
          separator + translation_hits + \
          separator + rule_position + \
          separator + successful_session + \
          separator + failed_session + \
          dest_match


# -----------------------------------------------------------------------
if PARAM.ldnat and not PARAM.lsnat:
  separator = "\t"
  # print field name on first line
  if not PARAM.noheader:
    print "zone_from"+separator+"rule_name"+separator+"ip_before_dnat"+separator+"subnet"+separator+"ip_source"+separator+"pool_name"+separator+"pool_ip"
    
  for daddr in nat_destination_rule_name:
    zone_from = nat_destination_rule_name[daddr][0][1]
    nat_rule_name = nat_destination_rule_name[daddr][0][2]
    nat_source_ip = nat_destination_rule_name[daddr][0][3]
    nat_pool_name = nat_destination_rule_name[daddr][0][4]
    nat_pool_ip = nat_destination_rule_name[daddr][0][5]
    print zone_from + \
          separator + nat_rule_name + \
          separator + daddr + \
          separator + daddr.split('/')[1] + \
          separator + ','.join(nat_source_ip) + \
          separator + nat_pool_name + \
          separator + nat_pool_ip





