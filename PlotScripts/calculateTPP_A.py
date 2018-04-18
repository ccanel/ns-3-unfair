# This program is used to plot throughput calculation from pcap file 

import sys
import os

for file_name in sys.argv[1:]:
    os.system("tshark -r " + file_name +" -T fields -e frame.time_relative -e frame.len -e ip.dst  >" + file_name[0:file_name.rindex('.')] + ".csv")
    f = open( 'plotmeTPP/TP-A.plotme', 'w')
    old_time = 2.0
    new_time =0
    val = 0
    totalval = 0
    p = 2.0
    with open(file_name[0:file_name.rindex('.')] + '.csv') as fq:
        fp = fq.readlines()
        for line in fp:
            if str(line.split('\t')[2]) == "10.0.21.2\n" and float(line.split('\t')[1]) == 1500 and float(line.split('\t')[0]) > 2.0:
                new_time = float(line.split('\t')[0])
                val += 1
                totalval +=1
                if (new_time - old_time > 0.1):
                    val = val/(new_time - old_time)
                    f.write(str(p) + " " + str(val) + "\n")
                    p += (new_time - old_time)
                    old_time = new_time
                    val = 0
        print 'A ' + str(totalval/new_time)
    f.close()
    os.remove(file_name[0:file_name.rindex('.')] + '.csv')
