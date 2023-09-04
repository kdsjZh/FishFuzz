#!/usr/bin/python3

import networkx as nx
import argparse
import json


def obtain_targ_list(fname):
  node_func_id = dict()
  with open(fname) as f:
    for line in f:
      node_name, func_id_str = line.strip('\n').split(',')
      node_func_id[node_name] = int(func_id_str)
  return node_func_id


def calc_all_distance(cg, node_func_id):
  all_dist_pair = dict(nx.all_pairs_dijkstra_path_length(cg))
  # convert to calldst
  all_calldst = dict()
  for src in all_dist_pair:
    for dst in all_dist_pair[src]:
      if src not in node_func_id or \
         dst not in node_func_id or \
         src == dst:
        continue
      src_id = node_func_id[src]
      dst_id = node_func_id[dst]
      if dst_id not in all_calldst:
        all_calldst[dst_id] = dict()
      all_calldst[dst_id][src_id] = all_dist_pair[src][dst]
  return all_calldst

if __name__ == "__main__":
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-i', type=str, required=True, help="Path to Temporary directory.")
  args = parser.parse_args()
  print ('[*] Loading and analyzing the callgraph...')
  cg = nx.DiGraph(nx.nx_pydot.read_dot('%s/callgraph.dot' % (args.i)))
  node_func_id = obtain_targ_list('%s/funcnode.csv' % (args.i))
  print ('[*] Calculating the distance...')
  all_calldst = calc_all_distance(cg, node_func_id)
  with open("%s/calldst.json" % (args.i), 'w') as f:
    json.dump(all_calldst, f)
  print ('[+] Finish the static distance calculation')