class Fault:
    def __init__(self, round, function, time, row, column):
        self._setRound(round)
        self._setFunction(function)
        self._setTime(time)
        self._setPosition(row, column)

    def _setRound(self, round):
        if 0 <= round < 11:
            self.round = round
        else:
            raise Exception("Invalid fault round number")

    def _setFunction(self, function):
        if function == "AddRoundKey":
            self.function = 0
        elif function == "SubBytes":
            self.function = 1
        elif function == "ShiftRows":
            self.function = 2
        elif function == "MixColumns":
            self.function = 3
        else:
            raise Exception("Invalid function name specified in fault")

    def _setTime(self, time):
        if time == "before":
            self.time = 0
        elif time == "after":
            self.time = 1
        else:
            raise Exception("Invalid time specified in fault")

    def _setPosition(self, row, column):
        if 0 <= row < 4 and 0 <= column < 4:
            self.row = row
            self.column = column
        else:
            raise Exception("Invalid position vector specified in fault")

    def description(self):
        string = map(str, [self.round, self.function, self.time, self.row, self.column])
        return ",".join(string)