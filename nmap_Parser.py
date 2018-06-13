#!/usr/bin/python3
from libnmap.parser import NmapParser
import argparse
import os
import sys


common_ports = ['21', '22', '23', '25', '80', '389', '443', '445', '1433', '3306', '3389', '5432', '5900', '8000', '8080', '8443']

def parsexml(files1):
    for file1 in files1:
        nmap_report = NmapParser.parse_fromfile(file1)
        for port in common_ports:
            list1 = [ a.address for a in nmap_report.hosts if (a.get_open_ports()) and int(port) in [b[0] for b in a.get_open_ports()] and 1 not in [b[0] for b in a.get_open_ports()] ]
            fileout = os.getcwd() + '/'+ port + '_hosts.txt'
            with open(fileout, 'a+') as f:
                for x in list1:
                    f.write(x.rstrip()+'\n')

def parsegnmap(files1):
    for file1 in files1:
        with open(file1, 'r') as f:
            for line in f:
                for port in common_ports:
                    fileout = os.getcwd() + '/' + port + '_hosts.txt'
                    with open(fileout, 'a+') as w:
                        checkport = ' ' + port + '/open/tcp//'
                        if checkport in line and '1/open/tcp//tcpmux' not in line:
                            lineout = line.split()
                            w.write(lineout[1].rstrip()+'\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--xml", help="Provide a Nmap XML file or files to parse", nargs="+")
    parser.add_argument("-g", "--gnmap", help="Provide a Nmap gnmap file or files to parse", nargs="+")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    if args.xml:
        parsexml(args.xml)
    if args.gnmap:
        parsegnmap(args.gnmap)
