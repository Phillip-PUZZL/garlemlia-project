import json
import os
import random

import tree

path_to_json = "C:\\Users\\driscoll_p\\RustroverProjects\\masters-project"

json_data = []
with open(os.path.join(path_to_json, "test_nodes.json")) as json_file:
    json_data = json.load(json_file)

node_list = []
for node in json_data:
    rt_list = []
    for hashes in node['routing_table']['buckets']:
        for id_info in node['routing_table']['buckets'][hashes]['nodes']:
            rt_id = f'{"{0:b}".format(int(id_info["id"], 16))}'.rjust(256, "0")
            rt_list.append(rt_id)

    rt_list.append(f'{"{0:b}".format(int(node["id"], 16))}'.rjust(256, "0"))

    temp_node = {'id': node["id"], 'id_bin': f'{"{0:b}".format(int(node["id"], 16))}'.rjust(256, "0"), 'routing_table': rt_list}
    node_list.append(temp_node)

while True:
    node = random.choice(node_list)
    tree.create_colored_graph_256bit(node["id_bin"], node["routing_table"])
    input("Press Enter to continue...")