import networkx as nx
from collections import deque
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout

class TreeNode:
    def __init__(self, label=""):
        self.label = label  # This is the "prefix" so far
        self.left = None
        self.right = None

def insert(root, bits):
    """
    Insert a single binary string (e.g., 128 bits) into the tree.
    Each node is labeled by the prefix that led there.
    """
    current = root
    prefix = ""
    for bit in bits:
        prefix += bit
        if bit == '0':
            if current.left is None:
                current.left = TreeNode(label=prefix)
            current = current.left
        else:
            if current.right is None:
                current.right = TreeNode(label=prefix)
            current = current.right

def build_tree(node_ids):
    """
    Build a binary tree from a list of binary strings (node_ids).
    The root node has label="".
    """
    root = TreeNode(label="")
    for bits in node_ids:
        insert(root, bits)
    return root

def tree_to_graph(root):
    """
    Convert the TreeNode structure to a NetworkX DiGraph.
    Each node's .label is used as the graph node name.
    """
    g = nx.DiGraph()
    queue = deque([root])
    visited = set()

    while queue:
        node = queue.popleft()
        if node not in visited:
            visited.add(node)
            g.add_node(node.label)  # use the node's label (prefix)

            if node.left:
                g.add_node(node.left.label)
                g.add_edge(node.label, node.left.label)
                queue.append(node.left)

            if node.right:
                g.add_node(node.right.label)
                g.add_edge(node.label, node.right.label)
                queue.append(node.right)

    return g

def compress_and_color(
    g,
    root_label="",
    node_id=None,
    all_inserted=None
):
    """
    Compress single-child chains in 'g' into a new DiGraph.
    Each compressed node:
      - has a single-bit display label (or " " if it's the true root)
      - is colored:
          BLUE if the chain includes node_id
          RED  if it includes any other from all_inserted
          LIGHTGRAY otherwise
    """
    if all_inserted is None:
        all_inserted = set()

    new_g = nx.DiGraph()
    visited = set()
    prefix_to_compressed = {}   # Map original prefix -> compressed node ID
    global_idx = 0             # to create short names like n0, n1, etc.

    def dfs_compress(prefix, parent_prefix):
        """
        DFS from 'prefix', compress a single-child chain.
        'parent_prefix' helps us figure out which single bit to display.
        Return the compressed node ID in new_g.
        """
        nonlocal global_idx

        if prefix in visited:
            return prefix_to_compressed[prefix]
        visited.add(prefix)

        # Collect a chain of single-child nodes starting from 'prefix'
        chain = [prefix]
        current = prefix
        while True:
            children = list(g.successors(current))
            if len(children) == 1:
                c = children[0]
                if c in visited:
                    break
                chain.append(c)
                visited.add(c)
                current = c
            else:
                break

        final_prefix = chain[-1]

        # Determine the single-bit label:
        #  If prefix == "" => we are the true root => label = " "
        #  Otherwise => label is final_prefix[len(parent_prefix)]
        if prefix == "":
            display_label = " "
        else:
            bit_index = len(parent_prefix)
            if len(final_prefix) > bit_index:
                display_label = final_prefix[bit_index]
            else:
                display_label = " "  # fallback for edge cases

        # Decide color:
        #  - If chain has node_id => "blue"
        #  - Else if chain intersects all_inserted => "red"
        #  - else => "lightgray"
        chain_set = set(chain)
        if node_id in chain_set:
            color = "blue"
        elif chain_set.intersection(all_inserted):
            color = "red"
        else:
            color = "lightgray"

        # Create a short name for this compressed node
        compressed_id = f"n{global_idx}"
        global_idx += 1

        # Add the node to new_g
        new_g.add_node(
            compressed_id,
            display_label=display_label,
            node_color=color
        )

        # Map each prefix in the chain to this compressed_id
        for cprefix in chain:
            prefix_to_compressed[cprefix] = compressed_id

        # If the final node has multiple children, link them individually
        children = list(g.successors(final_prefix))
        if len(children) > 1:
            for c in children:
                cid = dfs_compress(c, final_prefix)
                new_g.add_edge(compressed_id, cid)

        return compressed_id

    # Start from the root label with parent_prefix=""
    dfs_compress(root_label, "")

    return new_g

def draw_compressed_tree(g, title="Compressed Tree"):
    """
    Draw the compressed graph top-to-bottom, with:
      - node label from 'display_label'
      - color from 'node_color'
    """
    pos = graphviz_layout(g, prog='dot', args='-Grankdir=TB')

    labels = {}
    colors = []
    for node in g.nodes():
        labels[node] = g.nodes[node].get("display_label", " ")
        colors.append(g.nodes[node].get("node_color", "lightgray"))

    nx.draw(g, pos, with_labels=False, arrows=True, node_color=colors)
    nx.draw_networkx_labels(g, pos, labels=labels)
    plt.title(title)
    plt.axis("off")
    plt.show()

def create_colored_graph_128bit(node_id, node_ids_128bit):
    """
    1) Build the raw tree from node_ids_128bit.
    2) Convert to Nx graph.
    3) Compress + color.
    4) Draw.
    """
    # 1) Build the tree
    root = build_tree(node_ids_128bit)

    # 2) Nx graph
    raw_g = tree_to_graph(root)

    # 3) Compress + color
    all_inserted = set(node_ids_128bit)
    compressed_g = compress_and_color(
        raw_g,
        root_label="",   # empty prefix is the real root
        node_id=node_id,
        all_inserted=all_inserted
    )

    # 4) Draw
    draw_compressed_tree(compressed_g, title=f"{node_id} Routing Table")
