# juniper-config-parser

## Synopsis

This parser will read the Juniper SRX config using SSH and pexpect.<br>
The goal of this Juniper project is to dig into SRX configuration file very easily through Linux command line in order to
- graph Zones and Rules
- export Policies into Excel CSV format (having counters, rule's position, etc)
- dig recursively into address-set
- list SNAT & DNAT and export it into an Excel CSV format
- list Application (port) to check doublon for example
- historize configuration file (this will be done automatically through an option in command line, if resquested by users)

## Code Example

* list SRX's Zones, Address-Set, Address-Set of a specific Zone <br>
./srx.py -lzone<br>
./srx.py -laddrset<br>
./srx.py -zoneaddrset Interne (this dig recursively into the address-set "Interne")<br>

* generate GraphViz file of all Policies between the zones DMZ & Interne<br>
./srx.py -rulestree DMZ-Interne -graphviz > DMZ-Interne.viz

* then, assuming Dot is installed on your system, the following command generate the JPEG representation of your Policies<br>
dot viz.viz -Tjpg -o DMZ-Interne.jpg

* display some potential inconsistencies in your SRX configuration file<br>
./srx.py -dspwarn

## Motivation

This script has been first developed at Cergy Pontoise University by JT Graveaud, IT Network and Infrastructure Manager.<br>
The first need of this script was to understand and to see policies, SNAT and DNAT more clearly in order to clean thousands of policies that became unreadable years after years. 

## Installation

------------------
Quick starting User's guide & useful command lines:
------------------
- 1/ First you need to set your config file "srx.conf"

$ cp srx_default.conf srx.conf

You need to edit this config file to set the srx_ip and srx_login of your SRX Device

srx_ip = 10.0.0.1<br>
srx_login = user-ro<br>

- 2/ Then you need to encrypt your SRX password in order to avoid

storing the password in a text format<br>
having a trace of the SRX password anywhere including in the bash history<br>
retyping everytime the password in the command line<br>

$ ../common/pysec.py --enc -k key_default.enc

- 3/ eventually get all SRX configuration data and SRX counters to get all those information in a text format
   and manipulate those data without fetching the SRX all the time.<br>
   This way you can historize SRX configuration file.
   
$ ./srx.py -getconf

Note: the command above generate the following configuration and counters in the txt Format stored in "./data" directory<br>
show configuration | display xml<br>
show configuration | display set<br>
show security policies hit-count<br>
show security policies<br>
show security nat source rule all<br>
show security nat destination rule all<br>

After, those 3 very first steps, you can start using ./srx.py

## Tests

Help on srx.py parameters : ./srx.py -h


## Contributors

The contributor is today JT Graveaud,<br>
but anyone who want to improve it to make it even more usefull to the entire community is really welcome.

## License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
