import networkx as nx

# Define a sample class
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def have_birthday(self):
        self.age += 1
        print(f"{self.name} is now {self.age} years old")

    def __repr__(self):
        return f"Person('{self.name}', {self.age})"

# Create a graph and add nodes with class instances
G = nx.Graph()

# Method 1: Store instance as node attribute
person1 = Person("Alice", 30)
G.add_node("node1", data=person1)

# Method 2: Store instance as the node itself
person2 = Person("Bob", 25)
G.add_node(person2)

# Method 3: Store instance in edge attributes
person3 = Person("Charlie", 35)
G.add_edge("node1", person2, manager=person3)

# Retrieve and modify instances
# From node attribute
alice = G.nodes["node1"]["data"]
print(f"Before: {alice}")
alice.have_birthday()
print(f"After: {alice}")
print(f"In graph: {G.nodes['node1']['data']}")  # Same object, changes reflected

print("\n" + "="*50 + "\n")

# From node (when instance IS the node)
bob = list(G.nodes())[1]  # Get Bob (the second node)
print(f"Before: {bob}")
bob.have_birthday()
print(f"After: {bob}")
print(f"In graph: {list(G.nodes())[1]}")  # Same object

print("\n" + "="*50 + "\n")

# From edge attribute
charlie = G.edges["node1", person2]["manager"]
print(f"Before: {charlie}")
charlie.have_birthday()
print(f"After: {charlie}")
print(f"In graph: {G.edges['node1', person2]['manager']}")  # Same object