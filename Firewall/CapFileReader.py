import os
import time
from scapy.all import rdpcap

class CapFileReader:

    def show(self, packets):

        if packets:
            for packet in packets:
                packet.show()
        else:
            print("No packets")

    def read(self, filePath):

        fileExists = os.path.isfile(filePath)

        if fileExists:

            print("=> Reading capture file...")

            time.sleep(1)

            packets = rdpcap(filePath)
            return packets

        else:
            print("File doesn't exists")

if __name__ == "__main__":
    print("This is a module file and it should not be executed.")