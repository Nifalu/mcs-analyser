from simple_analyzer import SimpleAnalyzer
from io_state import IOState, IOSnapshot




def example1():
    """
    Each binary has 1 input and 1 output and produces 1 solution (per output)
    => run each binary once
    """

    binaries = ["./bin/lessThan16_x86",
                "./bin/moreThan8_x86",
                "./bin/equal10_x86"]

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


def example2():
    """
    Binary A produces 2 Solutions, binary B takes 1 input.
    => need to run B twice
    """

    binaries = ["./bin/twoSolutionsA_x86",
                "./bin/twoSolutionsB_x86",]

    initial_input = IOState.unconstrained("input", 64)

    sa1 = SimpleAnalyzer(binaries[0], [initial_input])
    first_result: IOSnapshot = sa1.analyze()
    first_result.print_rich()

    sa2 = SimpleAnalyzer(binaries[1], [first_result.outputs[0]]) # pass first solution of first to the next analyzer
    second_result: IOSnapshot = sa2.analyze()
    second_result.print_rich()

    sa3 = SimpleAnalyzer(binaries[1], [first_result.outputs[1]]) # pass second solution of first to the next analyzer
    third_result: IOSnapshot = sa3.analyze()
    third_result.print_rich()


def example3():
    """
    Binary C takes 2 inputs, need to pass Outputs of A and B
    :return:
    """

    binaries = ["./bin/lessThan16_x86",
                "./bin/moreThan8_x86",
                "./bin/twoInputs_x86"]

    initial_input_A = IOState.unconstrained("inputA", 64)
    initial_input_B = IOState.unconstrained("inputB", 64)

    sa1 = SimpleAnalyzer(binaries[0], [initial_input_A])
    first_result: IOSnapshot = sa1.analyze()
    first_result.print_rich()

    sa2 = SimpleAnalyzer(binaries[1], [initial_input_B])
    second_result: IOSnapshot = sa2.analyze()
    second_result.print_rich()

    merged_outputs = first_result.outputs + second_result.outputs

    sa3 = SimpleAnalyzer(binaries[2], merged_outputs) # pass outputs of first and second to the next analyzer
    third_result: IOSnapshot = sa3.analyze()
    third_result.print_rich()




def main():
    # example1()
    # example2()
    example3()


if __name__ == "__main__":
    main()