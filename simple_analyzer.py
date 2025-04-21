import angr

"""
binary is compiled with:
docker run --platform linux/amd64 --rm -v $(pwd):/work -w /work gcc:latest gcc -g -O0 bin/simple.c -o bin/simple_x86
"""

BINARY = "./bin/simple_x86"
"""
#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t x;

    printf("Enter a number: ");
    scanf("%u", &x);

    printf("You entered: %u\n", x);

    if ((x > 10 && x < 15) || (x > 20 && x < 25)) {
        printf("Path A\n");
    } else {
        printf("Path B\n");
    }

    return 0;
}
"""

class ScanfHook(angr.SimProcedure):
    def run(self, fmt, ptr):
        # Simulate a scanf reading by using a symbolic variable
        x = self.state.solver.BVS('x', 32)
        # store the value in the memory location pointed to by ptr
        self.state.memory.store(ptr, x, endness=self.state.arch.memory_endness)
        # save the variable in state.globals for easy access
        self.state.globals['x'] = x

        return 1

def find_all_solutions_for_a():
    proj = angr.Project(BINARY, auto_load_libs=False)
    proj.hook_symbol('__isoc99_scanf', ScanfHook())

    state = proj.factory.entry_state(add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    })

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(
        find=lambda s: b"Path A" in s.posix.dumps(1),
        num_find=10,
    )
    for i, found_state in enumerate(simgr.found):
        if 'x' in found_state.globals:
            input_value = found_state.globals['x']
            min_val = found_state.solver.min(input_value)
            max_val =found_state.solver.max(input_value)
            constraints = str(found_state.solver.constraints)
            # Avoid printing too long constraints
            if len(constraints) > 250:
                constraints = constraints[:250] + "..."

            print(f"\nSolution {i+1}:")
            print(f"Found a path to Path A with input: {input_value}")
            print(f"Min value for x: {min_val}")
            print(f"Max value for x: {max_val}")
            print(f"Constraints for Path A: {constraints}")

if __name__ == "__main__":
    find_all_solutions_for_a()