Concept: Tree Resolution & Sparse Trees
Explanation:

A “Resolution” is the list of nodes that “represent” a subtree when the root of that subtree is blank. If a node is not blank, its resolution is just itself. If it is blank, its resolution is the union of the resolutions of its children.

Analogy:

Imagine a building where a floor manager is missing (a blank node). To give a message to that floor, you can’t give it to the manager, so you must give a copy to every active department head on that floor (the resolution).




Pseudocode for Resolution (RFC 9420, Section 5.4):

BEGIN Resolve(Node n)
IF n is not BLANK:
    RETURN [n]
IF n is LEAF and BLANK:
    RETURN []
ELSE:
    RETURN Resolve(n.left_child) + Resolve(n.right_child)
END Resolve
