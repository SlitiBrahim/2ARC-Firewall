import argparse
from Firewall.Firewall import Firewall
from scapy.all import *

def parse_passed_args():

    # instanciate an args parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-f", "--file", help="Read a capture file and display its content")
    parser.add_argument("-s", "--sniff", help="Sniff packets", action="store_true")

    return parser.parse_args()

def main():
    # Parsecommand-line options
    args = parse_passed_args()
     # Turns Namespace object to dictionnary
    args = vars(args)
    # Instanciate a new firewall
    firewall = Firewall()

    # Do a copy of args to only keep real passed args
    argsCopy = args.copy()
    for arg in args:
        if args[arg] is False or args[arg] is None:   # By default value of an not passed value is None
            del argsCopy[arg] # Delete entry in args dictionnary

    # get "real" passed args length
    argsLength = len(argsCopy)  # passed args length

    # More than one argument passed
    if argsLength > 1:
        print(str(argsLength) + " args passed, please provide one command at a time.")
    elif argsLength == 1:
        # if a "file" option was passed to program execution
        if args['file']:
            # Load packets from capture file passed to arguments
            packets = firewall.capFileReader.read(args['file'])
            # Show packets to stdout
            firewall.capFileReader.show(packets)
        elif args['sniff']:
            firewall.sniff()
    else:   # Any passed args
        print("No options passed, please type \"--help\" for help.")


if __name__ == "__main__":
    main()
