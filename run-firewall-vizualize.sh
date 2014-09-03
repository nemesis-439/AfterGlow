#!/bin/bash


#firewall-axenta-portscan 
#cut -d, -f3,5,6,7  $1 | uniq | sort | uniq | perl5.16 -I/Users/ksim/perl5/lib/perl5/Text/  ./afterglow.pl -c firewall-axenta-portscan.properties -e4 | dot -Gnormalize=true -Gsplines=true -Tpng -o fw-portscan.png


#firewall-axenta-machinescan 
#cut -d, -f3,5,7  $1 | uniq | sort | uniq | perl5.16 -I/Users/ksim/perl5/lib/perl5/Text/  ./afterglow.pl -c firewall-axenta-machinescan.properties -t -e 4 | neato -Gnormalize=true -Gsplines=true -Tpng -o fw-machine-scan.png


#firewall-axenta-machinescan-sameport 
#gawk -v FS=, -v OFS=, '{print $3,$6,$5,$7}' $1 | uniq | sort | uniq | perl5.16 -I/Users/ksim/perl5/lib/perl5/Text/  ./afterglow.pl -c firewall-axenta-machinescan-sameport.properties -e 4 | neato -Gnormalize=true -Gsplines=true -Tpng -o fw-machine-sameport.png

gawk -f convert_csv.awk $1 > fw.csv

# SRCIP DSTIP PORT ACTION
cut -d, -f3,5,6,7 fw.csv| uniq | sort | uniq | tee fw-temp.csv | perl5.16 -I/Users/ksim/perl5/lib/perl5/Text/  ./afterglow.pl -c firewall-axenta-portscan.properties -e 4  | neato -Gnormalize=true -Gsplines=true -Tpng -o fw-portscan.png

# SRCIP DSTIP  ACTION
cut -d, -f1,2,4  fw-temp.csv | uniq | perl5.16 -I/Users/ksim/perl5/lib/perl5/Text/  ./afterglow.pl -c firewall-axenta-machinescan.properties -t -e 4 | neato -Gnormalize=true -Gsplines=true -Tpng -o fw-machine-scan.png

# SRCIP PORT DSTIP ACTION
gawk -v FS=, -v OFS=, '{print $1,$3,$2,$4}' fw-temp.csv | perl5.16 -I/Users/ksim/perl5/lib/perl5/Text/  ./afterglow.pl -c firewall-axenta-machinescan-sameport.properties -e 4 | neato -Gnormalize=true -Gsplines=true -Tpng -o fw-machine-sameport.png

#rm fw-temp.csv
#rm fw.csv
