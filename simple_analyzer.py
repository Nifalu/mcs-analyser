import angr
import claripy

BINARY = "./bin/simple_x86"
"""
int main() {
    uint32_t x;

    printf("Enter a number: ");
    scanf("%u", &x);

    printf("You entered: %u\n", x);

    if (x > 10 && x < 15) {
        printf("Path A (x > 10 && x < 15)\n");
    } else {
        printf("Path B\n");
    }

    return 0;
}
"""

def main():
    proj = angr.Project(BINARY, auto_load_libs=False)
    state = proj.factory.entry_state(stdin=angr.SimFile)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=lambda s: b"Path A" in s.posix.dumps(1))
    if len(simgr.found) > 0:
        found = simgr.found[0]
        print("Found a path to Path A:")
        print(found.posix.dumps(0))  # Input to the program
        print(found.posix.dumps(1))  # Output from the program
    else:
        print("No path found to Path A.")


if __name__ == "__main__":
    main()