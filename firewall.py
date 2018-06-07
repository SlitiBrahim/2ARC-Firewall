import argparse
from Firewall.Firewall import Firewall
from Firewall.Rule import Rule
from Firewall.Chain import Chain
from scapy.all import *


def parse_passed_args():

    # instanciate an args parser
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-f", "--file", help="Read a capture file and display its content")
    parser.add_argument(
        "-s", "--sniff", help="Sniff packets", action="store_true")
    parser.add_argument("-a", "--add", help="Add rule", action="store_true")
    parser.add_argument("-r", "--run", help="Run firewall with predefined rules", action="store_true")

    return parser.parse_args()


def main():
    # Parsecommand-line options
    args = parse_passed_args()
    # Turns Scapy's Namespace object to dictionnary
    args = vars(args)
    # Instanciate a new firewall
    firewall = Firewall()

    # Make a copy of args to only keep real passed args
    argsCopy = args.copy()
    for arg in args:
        # By default value of a not passed value is None
        if args[arg] is False or args[arg] is None:
            del argsCopy[arg]  # Delete entry in args dictionnary

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
        elif args['add']:
            rule = Rule.define_new_one()
            # check if we get back a rule, not any error
            if rule:
                firewall.get_chain().add_rule(rule)
        elif args['run']:
            firewall.run()
    else:   # Any passed args
        print("No options passed, please type \"--help\" for help.")

if __name__ == "__main__":
    main()
