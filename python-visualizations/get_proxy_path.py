import re
from datetime import datetime

import matplotlib.pyplot as plt
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
from scipy.stats import false_discovery_control


def visualize_routes_with_graphviz(logfile, root_node="127.0.0.1:6000"):
    """
    Builds a pruned graph: any chain that ends with NOT FORWARDING is rolled back
    to the last pivot (either the root node or a PROXY node). Everything after that
    pivot on that chain is removed.
    """

    # Regex patterns
    forward_pattern = re.compile(
        r"FINDPROXY\s+([\w\d]+)\[(\d+)\]\s+::\s+(127\.0\.0\.1:\d+)\s*->\s*(127\.0\.0\.1:\d+)"
    )
    proxy_pattern = re.compile(r"PROXY\s+::\s+(127\.0\.0\.1:\d+)")
    not_forward_pattern = re.compile(
        r"NOT FORWARDING\s+([\w\d]+)\[(\d+)\]\s+::\s+(127\.0\.0\.1:\d+)"
    )

    # Track which nodes are proxies, which are known not-forwarding
    proxies = set()
    not_forwarding_nodes = set()

    # For each (msg_id, msg_idx), store:
    #  {
    #    'nodes': [in order of first appearance],
    #    'terminated': False,
    #    'not_fwd_node': None   # node that triggered NOT FORWARDING, if any
    #  }
    chains = {}

    # Helper to add a new link in chain
    def add_link(msg_id, msg_idx, from_node, to_node):
        """Append from_node and to_node in order, if not present yet."""
        key = (msg_id, msg_idx)
        data = chains.setdefault(key,
            {'nodes': [], 'terminated': False, 'not_fwd_node': None}
        )
        # If chain is already 'terminated', do nothing
        if data['terminated']:
            return

        # Make sure from_node is in the path first
        # If from_node not in data['nodes'], append it
        if not data['nodes'] or data['nodes'][-1] != from_node:
            if from_node not in data['nodes']:
                data['nodes'].append(from_node)

        # Then append to_node if not already last in the list
        if not data['nodes'] or data['nodes'][-1] != to_node:
            data['nodes'].append(to_node)

    with open(logfile, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # FORWARD ...
            m_fwd = forward_pattern.search(line)
            if m_fwd:
                msg_id, idx_str, from_node, to_node = m_fwd.groups()
                add_link(msg_id, int(idx_str), from_node, to_node)
                continue

            # PROXY ...
            m_prx = proxy_pattern.search(line)
            if m_prx:
                node = m_prx.group(1)
                proxies.add(node)
                continue

            # NOT FORWARDING ...
            m_notfwd = not_forward_pattern.search(line)
            if m_notfwd:
                msg_id, idx_str, node = m_notfwd.groups()
                not_forwarding_nodes.add(node)

                key = (msg_id, int(idx_str))
                if key not in chains:
                    chains[key] = {
                        'nodes': [node],   # at least store the node
                        'terminated': True,
                        'not_fwd_node': node
                    }
                else:
                    chains[key]['terminated'] = True
                    chains[key]['not_fwd_node'] = node

    # ---------------------------------------------------------------------
    # POST-PROCESS the chains to "retroactively prune" from last pivot
    # if it ended in NOT FORWARDING
    # ---------------------------------------------------------------------
    def is_pivot(n):
        """Return True if n is the 'root_node' or in proxies."""
        return (n == root_node) or (n in proxies)

    for key, data in chains.items():
        if data['terminated'] and data['not_fwd_node'] is not None:
            # The chain ended in NOT FORWARDING at that node
            # We want to remove everything from the last pivot (inclusive or exclusive?)
            # Actually, we keep the pivot itself, so we cut from pivot+1 onward.
            nfn = data['not_fwd_node']  # the node that triggered NOT FORWARDING
            if nfn in data['nodes']:
                idx_nfn = data['nodes'].index(nfn)
                # Walk backward from idx_nfn to find the last pivot
                # If none found, we remove everything (or keep the earliest node if you prefer).
                pivot_idx = None
                for i in range(idx_nfn, -1, -1):
                    if is_pivot(data['nodes'][i]):
                        pivot_idx = i
                        break
                if pivot_idx is not None:
                    # Keep everything up to pivot_idx (including the pivot), then remove the rest
                    data['nodes'] = data['nodes'][: pivot_idx + 1]
                else:
                    # No pivot found at all => keep nothing, or keep up to zero
                    data['nodes'] = []
            else:
                # If the not_fwd_node wasn't actually in the chain's nodes for some reason,
                # you could decide to remove the entire chain or do nothing.
                data['nodes'] = []

    # ---------------------------------------------------------------------
    # BUILD THE GRAPH from pruned node-lists
    # ---------------------------------------------------------------------
    G = nx.DiGraph()

    # Reconstruct edges from the chain's node lists
    # e.g. if chain 'nodes' = [A, B, C], we add edges (A->B), (B->C)
    for (msg_id, msg_idx), data in chains.items():
        node_list = data['nodes']
        for i in range(len(node_list) - 1):
            src = node_list[i]
            dst = node_list[i+1]
            # We attach 'msg_idx' so you can color edges by index
            edge_seq = i + 1
            G.add_edge(src, dst, msg_idx=msg_idx, chain_seq=edge_seq)

    # Make sure we add stand-alone proxy or not-forwarding nodes
    for node in proxies:
        if node not in G:
            G.add_node(node)

    # ---------------------------------------------------------------------
    # LAYOUT & PLOT
    # ---------------------------------------------------------------------
    pos = graphviz_layout(
        G,
        prog="neato",
        args='-Goverlap=false -Gsep=1.0 -Gmindist=1.0 -Gmaxiter=2000 -GK=0.9'
    )

    # Distinguish sets of nodes for coloring
    proxy_nodes = set(proxies)
    not_fwd_nodes = set(not_forwarding_nodes)

    normal_nodes = [n for n in G.nodes()
                    if n not in proxy_nodes and n not in not_fwd_nodes]

    # If root_node is in normal, we want to style it specially
    if root_node in normal_nodes:
        normal_nodes.remove(root_node)

    fig, ax = plt.subplots(figsize=(45, 30))

    # Edge coloring
    edge_indices = [d["msg_idx"] for _, _, d in G.edges(data=True)]
    if edge_indices:
        vmin, vmax = min(edge_indices), max(edge_indices)
    else:
        vmin, vmax = 0, 1
    cmap = plt.cm.plasma

    nx.draw_networkx_edges(
        G, pos,
        ax=ax,
        arrowstyle="-|>",
        arrowsize=10,
        edge_color=edge_indices,
        edge_cmap=cmap,
        edge_vmin=vmin,
        edge_vmax=vmax
    )

    # Draw normal nodes
    node_size = 600
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=normal_nodes,
        node_size=node_size,
        node_color="lightblue",
        ax=ax
    )

    # Root node in red, bigger
    if root_node in G:
        nx.draw_networkx_nodes(
            G, pos,
            nodelist=[root_node],
            node_size=int(node_size * 1.4),
            node_color="red",
            ax=ax
        )

    # Proxy nodes in green squares
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=proxy_nodes,
        node_shape="s",
        node_size=node_size,
        node_color="green",
        ax=ax
    )

    # Label the nodes (strip off the "127.0.0.1:" prefix)
    labels = {n: n.replace("127.0.0.1:", "") for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, ax=ax)
    edge_labels = {
        (u, v): f'{d["chain_seq"]}'
        for u, v, d in G.edges(data=True)
    }
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    ax.set_title("PROXY ROUTES",
                 fontsize=14)
    ax.axis("off")
    plt.show()


def visualize_one_route_with_graphviz(logfile, root_node="127.0.0.1:6000"):
    """
    Builds a pruned graph: any chain that ends with NOT FORWARDING is rolled back
    to the last pivot (either the root node or a PROXY node). Everything after that
    pivot on that chain is removed.
    """

    # Regex patterns
    forward_pattern = re.compile(
        r"FINDPROXY\s+([\w\d]+)\[(\d+)\]\s+::\s+(127\.0\.0\.1:\d+)\s*->\s*(127\.0\.0\.1:\d+)"
    )
    proxy_pattern = re.compile(r"PROXY\s+::\s+(127\.0\.0\.1:\d+)")
    not_forward_pattern = re.compile(
        r"NOT FORWARDING\s+([\w\d]+)\[(\d+)\]\s+::\s+(127\.0\.0\.1:\d+)"
    )

    # Track which nodes are proxies, which are known not-forwarding
    proxies = set()
    not_forwarding_nodes = set()

    # For each (msg_id, msg_idx), store:
    #  {
    #    'nodes': [in order of first appearance],
    #    'terminated': False,
    #    'not_fwd_node': None   # node that triggered NOT FORWARDING, if any
    #  }
    chains = {}

    # Helper to add a new link in chain
    def add_link(msg_id, msg_idx, from_node, to_node):
        """Append from_node and to_node in order, if not present yet."""
        key = (msg_id, msg_idx)
        data = chains.setdefault(key,
            {'nodes': [], 'terminated': False, 'not_fwd_node': None}
        )
        # If chain is already 'terminated', do nothing
        if data['terminated']:
            return

        # Make sure from_node is in the path first
        # If from_node not in data['nodes'], append it
        if not data['nodes'] or data['nodes'][-1] != from_node:
            if from_node not in data['nodes']:
                data['nodes'].append(from_node)

        # Then append to_node if not already last in the list
        if not data['nodes'] or data['nodes'][-1] != to_node:
            data['nodes'].append(to_node)

    with open(logfile, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # FORWARD ...
            m_fwd = forward_pattern.search(line)
            if m_fwd:
                msg_id, idx_str, from_node, to_node = m_fwd.groups()
                add_link(msg_id, int(idx_str), from_node, to_node)
                continue

            # PROXY ...
            m_prx = proxy_pattern.search(line)
            if m_prx:
                node = m_prx.group(1)
                proxies.add(node)
                continue

            # NOT FORWARDING ...
            m_notfwd = not_forward_pattern.search(line)
            if m_notfwd:
                msg_id, idx_str, node = m_notfwd.groups()
                not_forwarding_nodes.add(node)

                key = (msg_id, int(idx_str))
                if key not in chains:
                    chains[key] = {
                        'nodes': [node],   # at least store the node
                        'terminated': True,
                        'not_fwd_node': node
                    }
                else:
                    chains[key]['terminated'] = True
                    chains[key]['not_fwd_node'] = node

    # ---------------------------------------------------------------------
    # POST-PROCESS the chains to "retroactively prune" from last pivot
    # if it ended in NOT FORWARDING
    # ---------------------------------------------------------------------
    def is_pivot(n):
        """Return True if n is the 'root_node' or in proxies."""
        return (n == root_node) or (n in proxies)

    for key, data in chains.items():
        if data['terminated'] and data['not_fwd_node'] is not None:
            # The chain ended in NOT FORWARDING at that node
            # We want to remove everything from the last pivot (inclusive or exclusive?)
            # Actually, we keep the pivot itself, so we cut from pivot+1 onward.
            nfn = data['not_fwd_node']  # the node that triggered NOT FORWARDING
            if nfn in data['nodes']:
                idx_nfn = data['nodes'].index(nfn)
                # Walk backward from idx_nfn to find the last pivot
                # If none found, we remove everything (or keep the earliest node if you prefer).
                pivot_idx = None
                for i in range(idx_nfn, -1, -1):
                    if is_pivot(data['nodes'][i]):
                        pivot_idx = i
                        break
                if pivot_idx is not None:
                    # Keep everything up to pivot_idx (including the pivot), then remove the rest
                    data['nodes'] = data['nodes'][: pivot_idx + 1]
                else:
                    # No pivot found at all => keep nothing, or keep up to zero
                    data['nodes'] = []
            else:
                # If the not_fwd_node wasn't actually in the chain's nodes for some reason,
                # you could decide to remove the entire chain or do nothing.
                data['nodes'] = []

    longest = 0
    longest_proxy = None
    for key, data in chains.items():
        if len(data['nodes']) > longest:
            longest = len(data['nodes'])
            longest_proxy = data['nodes'][len(data['nodes']) - 1]

    remove_list = []
    longest_found_route = 0
    for key, data in chains.items():
        if longest_proxy not in data['nodes']:
            remove_list.append(key)
        else:
            start_removing = False
            remove_node_list = []
            for node in data['nodes']:
                if node == longest_proxy:
                    start_removing = True
                    continue
                if start_removing:
                    remove_node_list.append(node)

            for node in remove_node_list:
                data['nodes'].remove(node)

            longest_found_route += 1

    for key in remove_list:
        del chains[key]

    proxies = [longest_proxy]

    # ---------------------------------------------------------------------
    # BUILD THE GRAPH from pruned node-lists
    # ---------------------------------------------------------------------
    G = nx.DiGraph()

    # Reconstruct edges from the chain's node lists
    # e.g. if chain 'nodes' = [A, B, C], we add edges (A->B), (B->C)
    for (msg_id, msg_idx), data in chains.items():
        node_list = data['nodes']
        for i in range(len(node_list) - 1):
            src = node_list[i]
            dst = node_list[i+1]
            # We attach 'msg_idx' so you can color edges by index
            edge_seq = i + 1
            G.add_edge(src, dst, msg_idx=msg_idx, chain_seq=edge_seq)

    # Make sure we add stand-alone proxy or not-forwarding nodes
    for node in proxies:
        if node not in G:
            G.add_node(node)

    # ---------------------------------------------------------------------
    # LAYOUT & PLOT
    # ---------------------------------------------------------------------
    pos = graphviz_layout(
        G,
        prog="neato",
        args='-Goverlap=false -Gsep=1.0 -Gmindist=1.0 -Gmaxiter=2000 -GK=0.9'
    )

    # Distinguish sets of nodes for coloring
    proxy_nodes = set(proxies)
    not_fwd_nodes = set(not_forwarding_nodes)

    normal_nodes = [n for n in G.nodes()
                    if n not in proxy_nodes and n not in not_fwd_nodes]

    # If root_node is in normal, we want to style it specially
    if root_node in normal_nodes:
        normal_nodes.remove(root_node)

    fig, ax = plt.subplots(figsize=(20, 15))

    # Edge coloring
    edge_indices = [d["msg_idx"] for _, _, d in G.edges(data=True)]
    if edge_indices:
        vmin, vmax = min(edge_indices), max(edge_indices)
    else:
        vmin, vmax = 0, 1
    cmap = plt.cm.plasma

    nx.draw_networkx_edges(
        G, pos,
        ax=ax,
        arrowstyle="-|>",
        arrowsize=10,
        edge_color=edge_indices,
        edge_cmap=cmap,
        edge_vmin=vmin,
        edge_vmax=vmax
    )

    # Draw normal nodes
    node_size = 600
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=normal_nodes,
        node_size=node_size,
        node_color="lightblue",
        ax=ax
    )

    # Root node in red, bigger
    if root_node in G:
        nx.draw_networkx_nodes(
            G, pos,
            nodelist=[root_node],
            node_size=int(node_size * 1.4),
            node_color="red",
            ax=ax
        )

    # Proxy nodes in green squares
    nx.draw_networkx_nodes(
        G, pos,
        nodelist=proxy_nodes,
        node_shape="s",
        node_size=node_size,
        node_color="green",
        ax=ax
    )

    # Label the nodes (strip off the "127.0.0.1:" prefix)
    labels = {n: n.replace("127.0.0.1:", "") for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, ax=ax)
    edge_labels = {
        (u, v): f'{d["chain_seq"]}'
        for u, v, d in G.edges(data=True)
    }
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    ax.set_title("PROXY ROUTE",
                 fontsize=14)
    ax.axis("off")
    plt.show()


def parse_and_sort_log(filepath, out_filepath):
    utc_lines = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith("2025") and "UTC" in line:
                match = re.match(r'^(2025-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\sUTC\s::\s(.*)', line)
                if match:
                    datetime_str = match.group(1)
                    rest_of_line = match.group(2)
                    # Trim extraneous fractional digits
                    datetime_str = re.sub(r'(\d{2}:\d{2}:\d{2}\.\d{6})\d+', r'\1', datetime_str)
                    dt = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
                    utc_lines.append((dt, line.rstrip("\n")))

    # Sort by datetime
    utc_lines.sort(key=lambda x: x[0])

    with open(out_filepath, "w", encoding="utf-8") as out:
        for _, original_line in utc_lines:
            out.write(original_line + "\n")


if __name__ == "__main__":
    # Example usage:
    parse_and_sort_log("garlemlia_sim_output.txt", "forward_history.txt")
    visualize_one_route_with_graphviz("forward_history.txt")
