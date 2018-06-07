from Firewall.Rule import Rule
import os

class Chain:

    def __init__(self, rules=[]):
        self.__rules = rules

    def __str__(self):
        if self.__rules:
            output = "Chain's rules:\n------------------------\nSource:\t\tAction:\t\t\n"

            for rule in self.__rules:
                output += rule.get_src() + " | " + rule.get_action()

        else:
            output = "No rules"

        return output

    def add_rule(self, rule):

        # if file already exists
        if os.path.isfile("rules.rl"):
            # parse rules in file
            rules = self.parse_file()
           
            if rules:
                # /!\ Don't forget to add before last index which contains default policy
                rules.append(rule)
                self.set_rules(rules)
            else: # file si empty
                # remove file and begin again
                os.remove("rules.rl")
                self.add_rule(rule)
        else:
            # /!\ Don't forget to add before last index which contains default policy
            self.__rules.append(rule)
            self.persist_in_file()

    def remove_rule(self, rule_index):
        try:
            rules = self.parse_file()
            rules.pop(rule_index)
        except:
            print("Chain's index dont exists")

    def get_rules(self):
        return self.parse_file()

    def set_rules(self, rules):
        self.__rules = rules
        self.persist_in_file()

    def parse_file(self):
        with open("rules.rl", "r") as rulesFile:
            data = rulesFile.readlines()

            # file is not empty
            if data:
                # clean data by filtering empty lines
                data = list(filter(lambda x: x != "\n", data))
                # remove "\n" in lines
                data = list(map(lambda x: x.replace("\n", ""), data))
                rules = list(map(lambda x: Rule.parse(x), data))
                return rules

    def persist_in_file(self):
        with open("rules.rl", "w") as rulesFile:

            # just write rules in file properly
            # if single or several rule(s)
            if len(self.__rules) >= 1:
                # write out rule without a line break
                rulesFile.write(self.__rules[0].serialize())

            # write rules except the first one that we already wrote out just above
            for rule in self.__rules[1:]:
                # write out each rule preceded by a line break
                rulesFile.write("\n" + rule.serialize())

