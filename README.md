# juniper-config-parser

## Synopsis

This parser will read the Juniper SRX config using SSH and pexpect.
The goal of this Juniper project is to dig into SRX configuration file very easily through Linux command line in order to
- graph Zones and Rules
- export Policies into Excel CSV format (having counters, rule's position, etc)
- dig recursively into address-set
- list SNAT & DNAT and export it into an Excel CSV format
- list Application (port) to check doublon for example

## Code Example

./srx.py -lzone
./srx.py -laddrset
./srx.py -zoneaddrset Interne (this dig recursively into the address-set "Interne")

### generate GraphViz file of all Policies between the zones DMZ & Interne
./srx.py -rulestree DMZ-Interne -graphviz > DMZ-Interne.viz
### then, assuming Dot is installed on your system, the following command generate the JPEG representation of your Policies
dot viz.viz -Tjpg -o DMZ-Interne.jpg

./srx.py -dspwarn

## Motivation

This script has been first developed at Cergy Pontoise University by JT Graveaud, IT Network and Infrastructure Manager.
The first need of this script was to understand and to see policies, SNAT and DNAT more clearly in order to clean thousands of policies that became unreadable years after years. 

## Installation

TODO : to be written

## Tests

Help on srx.py parameters : ./srx.py -h


## Contributors

The contributor is today JT Graveaud, 
but anyone who want to improve it to make it even more usefull to the entire community is really welcome.

## License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
