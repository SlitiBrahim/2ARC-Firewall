class Rule:

    def __init__(self, src="", action="DROP"):
        self.__src = src
        self.__action = action.lower()

    def get_src(self):
        return self.__src

    def get_action(self):
        return self.__action

    def set_src(self, src):
        # do src verification
        self.__src = src

    def set_action(self, action):
        # do src verification
        self.__action = action

    def serialize(self):
        return self.__src + ";" + self.__action

    @staticmethod
    def parse(str):
        data = str.split(";")
        return Rule(data[0], data[1].lower())

    @staticmethod
    def define_new_one():

        src = input("Enter an IP source or press enter: ")
        # do verification

        action = input("Enter the action you want to execute when a packet match that rule, DROP(default) or ACCEPT:")
        # do verification

        # return an error if verifications failed
        return Rule(src, action)
