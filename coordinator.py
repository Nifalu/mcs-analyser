from simple_analyzer import SimpleAnalyzer
from io_state import IOState, IOSnapshot



def main():

    binaries = ["./bin/lessThan16_x86",
                "./bin/moreThan8_x86",
                "./bin/equal10_x86",]

    initial_input = IOState.unconstrained("input", 64)

    sa1 = SimpleAnalyzer(binaries[0], [initial_input])
    first_result: IOSnapshot = sa1.analyze()
    first_result.print_rich()

    sa2 = SimpleAnalyzer(binaries[1], first_result.outputs) # pass outputs of first to the next analyzer
    second_result: IOSnapshot = sa2.analyze()
    second_result.print_rich()

    sa3 = SimpleAnalyzer(binaries[2], second_result.outputs) # pass outputs of second to the next analyzer
    third_result: IOSnapshot = sa3.analyze()
    third_result.print_rich()

if __name__ == "__main__":
    main()