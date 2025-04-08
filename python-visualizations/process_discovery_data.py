import re
from collections import Counter

from matplotlib import pyplot as plt


def process_file(filename):
    pattern = re.compile(r'TOTAL HOPS:\s+(\d+)\s+N1 HOPS:\s+(\d+)\s+N2 HOPS:\s+(\d+)\s+SN:\s+(\d+)')

    data = []
    with open(filename, 'r') as infile:
        for line in infile:
            match = pattern.search(line)
            if match:
                total_hops_str, n1_hops_str, n2_hops_str, sn_str = match.groups()
                total_hops = int(total_hops_str)
                n1_hops = int(n1_hops_str)
                n2_hops = int(n2_hops_str)

                # Store the values in a dictionary or tuple (whichever you prefer):
                data.append({
                    "total_hops": total_hops,
                    "n1_hops": n1_hops,
                    "n2_hops": n2_hops,
                    "sn": sn_str
                })
    return data


def process_file_no_adjacent_proxies(filename):
    pattern = re.compile(r'TOTAL HOPS:\s+(\d+)\s+N1 HOPS:\s+(\d+)\s+N2 HOPS:\s+(\d+)\s+SN:\s+(\d+)')

    data = []
    with open(filename, 'r') as infile:
        for line in infile:
            match = pattern.search(line)
            if match:
                total_hops_str, n1_hops_str, n2_hops_str, sn_str = match.groups()
                total_hops = int(total_hops_str)
                n1_hops = int(n1_hops_str)
                n2_hops = int(n2_hops_str)

                # Store the values in a dictionary or tuple (whichever you prefer):
                if n1_hops != 0 and n2_hops != 0:
                    data.append({
                        "total_hops": total_hops,
                        "n1_hops": n1_hops,
                        "n2_hops": n2_hops,
                        "sn": sn_str
                    })
    return data


proxy_counts = []
proxy_total_hops = []
proxy_n1_hops = []
proxy_n2_hops = []
all_singular_hops = []

for i in range(5):
    for j in range(100):
        results = process_file(f"./discovery_data/{i}_{j}.txt")
        proxy_counts.append(len(results))
        for entry in results:
            proxy_total_hops.append(entry['total_hops'])
            proxy_n1_hops.append(entry['n1_hops'])
            proxy_n2_hops.append(entry['n2_hops'])
            all_singular_hops.append(entry['n1_hops'])
            all_singular_hops.append(entry['n2_hops'])

average_proxy_counts = sum(proxy_counts) / len(proxy_counts)
average_total_hops = sum(proxy_total_hops) / len(proxy_total_hops)
average_n1_hops = sum(proxy_n1_hops) / len(proxy_n1_hops)
average_n2_hops = sum(proxy_n2_hops) / len(proxy_n2_hops)

print(f"Average .95 proxy counts: {average_proxy_counts}")
print(f"Average .95 total hops: {average_total_hops}")
print(f"Average .95 n1 hops: {average_n1_hops}")
print(f"Average .95 n2 hops: {average_n2_hops}")

proxy_counts_counter = Counter(proxy_counts)
total_hops_counter = Counter(proxy_total_hops)
n1_hops_counter = Counter(proxy_n1_hops)
n2_hops_counter = Counter(proxy_n2_hops)
all_hops_counter = Counter(all_singular_hops)

x = sorted(proxy_counts_counter.keys())
y = [proxy_counts_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxies')
plt.ylabel('Count')
plt.title('Distribution of Proxies Found; P=.95')
#plt.show()
plt.savefig("./Good Figures/proxies_count_95.png")
plt.clf()

x = sorted(total_hops_counter.keys())
y = [total_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxy Hops')
plt.ylabel('Count')
plt.title('Distribution of Total Proxy Hops; P=.95')
#plt.show()
plt.savefig("./Good Figures/total_hops_95.png")
plt.clf()

x = sorted(all_hops_counter.keys())
y = [all_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Individual Chain Hops')
plt.ylabel('Count')
plt.title('Distribution of Individual Chain Hops; P=.95')
#plt.show()
plt.savefig("./Good Figures/individual_hops_95.png")
plt.clf()

proxy_counts = []
proxy_total_hops = []
proxy_n1_hops = []
proxy_n2_hops = []
all_singular_hops = []

for i in range(5):
    for j in range(100):
        results = process_file(f"./discovery_data_2/{i}_{j}.txt")
        proxy_counts.append(len(results))
        for entry in results:
            proxy_total_hops.append(entry['total_hops'])
            proxy_n1_hops.append(entry['n1_hops'])
            proxy_n2_hops.append(entry['n2_hops'])
            all_singular_hops.append(entry['n1_hops'])
            all_singular_hops.append(entry['n2_hops'])

average_proxy_counts = sum(proxy_counts) / len(proxy_counts)
average_total_hops = sum(proxy_total_hops) / len(proxy_total_hops)
average_n1_hops = sum(proxy_n1_hops) / len(proxy_n1_hops)
average_n2_hops = sum(proxy_n2_hops) / len(proxy_n2_hops)

print(f"Average .90 proxy counts: {average_proxy_counts}")
print(f"Average .90 total hops: {average_total_hops}")
print(f"Average .90 n1 hops: {average_n1_hops}")
print(f"Average .90 n2 hops: {average_n2_hops}")

proxy_counts_counter = Counter(proxy_counts)
total_hops_counter = Counter(proxy_total_hops)
n1_hops_counter = Counter(proxy_n1_hops)
n2_hops_counter = Counter(proxy_n2_hops)
all_hops_counter = Counter(all_singular_hops)

x = sorted(proxy_counts_counter.keys())
y = [proxy_counts_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxies')
plt.ylabel('Count')
plt.title('Distribution of Proxies Found; P=.90')
#plt.show()
plt.savefig("./Good Figures/proxies_count_90.png")
plt.clf()

x = sorted(total_hops_counter.keys())
y = [total_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxy Hops')
plt.ylabel('Count')
plt.title('Distribution of Total Proxy Hops; P=.90')
#plt.show()
plt.savefig("./Good Figures/total_hops_90.png")
plt.clf()

x = sorted(all_hops_counter.keys())
y = [all_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Individual Chain Hops')
plt.ylabel('Count')
plt.title('Distribution of Individual Chain Hops; P=.90')
#plt.show()
plt.savefig("./Good Figures/individual_hops_90.png")
plt.clf()





proxy_counts = []
proxy_total_hops = []
proxy_n1_hops = []
proxy_n2_hops = []
all_singular_hops = []

for i in range(5):
    for j in range(100):
        results = process_file_no_adjacent_proxies(f"./discovery_data/{i}_{j}.txt")
        proxy_counts.append(len(results))
        for entry in results:
            proxy_total_hops.append(entry['total_hops'])
            proxy_n1_hops.append(entry['n1_hops'])
            proxy_n2_hops.append(entry['n2_hops'])
            all_singular_hops.append(entry['n1_hops'])
            all_singular_hops.append(entry['n2_hops'])

average_proxy_counts = sum(proxy_counts) / len(proxy_counts)
average_total_hops = sum(proxy_total_hops) / len(proxy_total_hops)
average_n1_hops = sum(proxy_n1_hops) / len(proxy_n1_hops)
average_n2_hops = sum(proxy_n2_hops) / len(proxy_n2_hops)

print(f"Average .95 proxy counts w/ no adjacency: {average_proxy_counts}")
print(f"Average .95 total hops w/ no adjacency: {average_total_hops}")
print(f"Average .95 n1 hops w/ no adjacency: {average_n1_hops}")
print(f"Average .95 n2 hops w/ no adjacency: {average_n2_hops}")

proxy_counts_counter = Counter(proxy_counts)
total_hops_counter = Counter(proxy_total_hops)
n1_hops_counter = Counter(proxy_n1_hops)
n2_hops_counter = Counter(proxy_n2_hops)
all_hops_counter = Counter(all_singular_hops)


x = sorted(proxy_counts_counter.keys())
y = [proxy_counts_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxies')
plt.ylabel('Count')
plt.title('Distribution of Proxies Found Excluding Adjacent Proxies; P=.95')
#plt.show()
plt.savefig("./Good Figures/proxies_count_95_no_adjacency.png")
plt.clf()

x = sorted(total_hops_counter.keys())
y = [total_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxy Hops')
plt.ylabel('Count')
plt.title('Distribution of Total Proxy Hops Excluding Adjacent Proxies; P=.95')
#plt.show()
plt.savefig("./Good Figures/total_hops_95_no_adjacency.png")
plt.clf()

x = sorted(all_hops_counter.keys())
y = [all_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Individual Chain Hops')
plt.ylabel('Count')
plt.title('Distribution of Individual Chain Hops Excluding Adjacent Proxies; P=.95')
#plt.show()
plt.savefig("./Good Figures/individual_hops_95_no_adjacency.png")
plt.clf()

proxy_counts = []
proxy_total_hops = []
proxy_n1_hops = []
proxy_n2_hops = []
all_singular_hops = []

for i in range(5):
    for j in range(100):
        results = process_file_no_adjacent_proxies(f"./discovery_data_2/{i}_{j}.txt")
        proxy_counts.append(len(results))
        for entry in results:
            proxy_total_hops.append(entry['total_hops'])
            proxy_n1_hops.append(entry['n1_hops'])
            proxy_n2_hops.append(entry['n2_hops'])
            all_singular_hops.append(entry['n1_hops'])
            all_singular_hops.append(entry['n2_hops'])

average_proxy_counts = sum(proxy_counts) / len(proxy_counts)
average_total_hops = sum(proxy_total_hops) / len(proxy_total_hops)
average_n1_hops = sum(proxy_n1_hops) / len(proxy_n1_hops)
average_n2_hops = sum(proxy_n2_hops) / len(proxy_n2_hops)

print(f"Average .90 proxy counts w/ no adjacency: {average_proxy_counts}")
print(f"Average .90 total hops w/ no adjacency: {average_total_hops}")
print(f"Average .90 n1 hops w/ no adjacency: {average_n1_hops}")
print(f"Average .90 n2 hops w/ no adjacency: {average_n2_hops}")

proxy_counts_counter = Counter(proxy_counts)
total_hops_counter = Counter(proxy_total_hops)
n1_hops_counter = Counter(proxy_n1_hops)
n2_hops_counter = Counter(proxy_n2_hops)
all_hops_counter = Counter(all_singular_hops)

x = sorted(proxy_counts_counter.keys())
y = [proxy_counts_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxies')
plt.ylabel('Count')
plt.title('Distribution of Proxies Found Excluding Adjacent Proxies; P=.90')
#plt.show()
plt.savefig("./Good Figures/proxies_count_90_no_adjacency.png")
plt.clf()

x = sorted(total_hops_counter.keys())
y = [total_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Proxy Hops')
plt.ylabel('Count')
plt.title('Distribution of Total Proxy Hops Excluding Adjacent Proxies; P=.90')
#plt.show()
plt.savefig("./Good Figures/total_hops_90_no_adjacency.png")
plt.clf()

x = sorted(all_hops_counter.keys())
y = [all_hops_counter[h] for h in x]
plt.bar(x, y)
plt.xlabel('Number of Individual Chain Hops')
plt.ylabel('Count')
plt.title('Distribution of Individual Chain Hops Excluding Adjacent Proxies; P=.90')
#plt.show()
plt.savefig("./Good Figures/individual_hops_90_no_adjacency.png")
plt.clf()