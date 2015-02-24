from threading import Thread
from random import randint
import time
import subprocess
import sys

def execute(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # Poll process for new output until finished
    while True:
        nextline = process.stdout.readline()

        if nextline == '' and process.poll() != None:
            break
        sys.stdout.write("::::::::::::::" + nextline)
#        sys.stdout.flush()

    output = process.communicate()[0]
    exitCode = process.returncode

    if (exitCode == 0):
        return output
    else:
        #raise ProcessException(command, exitCode, output)
        print 'fup'

execute(["click node_gatewayselector.click MESH_IFNAME=mesh0 MESH_IP_ADDR=192.168.42.148 MESH_ETH=e8:de:27:09:06:20 MESH_NETWORK=192.168.42.0/24 FAKE_IP=10.0.0.1 FAKE_ETH=1A-2B-3C-4D-5E-6F FAKE_NETWORK=10.0.0.1/24"])
