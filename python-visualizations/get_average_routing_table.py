import json
import os

path_to_json = "C:\\Users\\driscoll_p\\RustroverProjects\\masters-project"

json_data = []
with open(os.path.join(path_to_json, "test_nodes.json")) as json_file:
    json_data = json.load(json_file)

routing_table_lengths = []
bucket_sizes = []
routing_table_bucket_counts = []

for node in json_data:
    temp_length = 0
    bucket_count = 0
    for hashes in node['routing_table']['buckets']:
        temp_length += len(node['routing_table']['buckets'][hashes]['nodes'])
        bucket_sizes.append(len(node['routing_table']['buckets'][hashes]['nodes']))
        bucket_count += 1

    routing_table_lengths.append(temp_length)
    routing_table_bucket_counts.append(bucket_count)

all_rt_lengths = 0
for length in routing_table_lengths:
    all_rt_lengths += length

all_rt_bucket_counts = 0
for bucket_count in routing_table_bucket_counts:
    all_rt_bucket_counts += bucket_count

all_bucket_sizes = 0
for bucket_size in bucket_sizes:
    all_bucket_sizes += bucket_size

print(f"Average Routing Table Length: {all_rt_lengths / len(routing_table_lengths)}")
print(f"Average Routing Table Bucket Count: {all_rt_bucket_counts / len(routing_table_bucket_counts)}")
print(f"Average Bucket Size: {all_bucket_sizes / len(bucket_sizes)}")