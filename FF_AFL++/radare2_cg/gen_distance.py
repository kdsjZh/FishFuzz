#!/usr/bin/python3

import networkx as nx
import argparse
import json


def find_node_addr(cg, addr):
  offset_idx = "0x%08x" % (int(addr, 16))
  return [n for n, d in cg.nodes(data=True) if offset_idx == n]

def node_to_addr(addr):
  return hex(int(addr, 16))

def obtain_targ_list(fname):
  targ_addr_id = {}
  with open(fname) as f:
    for line in f:
      func_name, addr_name, offset = line.strip('\n').split(',')
      try:
        targ_addr_id[addr_name] = int(offset, 16)
      except:
        continue
  return targ_addr_id


def calc_all_distance(cg, targ_addr_id):
  func_list = [find_node_addr(cg, node)[0] for node in targ_addr_id.keys() if find_node_addr(cg, node) != []]
  all_dist_pair = dict(nx.all_pairs_dijkstra_path_length(cg))
  # convert to calldst
  all_calldst = {}
  for src in all_dist_pair:
    for dst in all_dist_pair[src]:
      if src not in func_list or dst not in func_list:
        continue
      if src != dst:
        src_id = targ_addr_id[node_to_addr(src)]
        dst_id = targ_addr_id[node_to_addr(dst)]
        if dst_id not in all_calldst:
          all_calldst[dst_id] = {}
        all_calldst[dst_id][src_id] = all_dist_pair[src][dst]
  return all_calldst

if __name__ == "__main__":
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-i', type=str, required=True, help="Path to directory containing funcmap, callgraph.")
  args = parser.parse_args()
  print ('[*] Loading and analyzing the dot...')
  cg = nx.DiGraph(nx.nx_pydot.read_dot('%s/callgraph.dot' % (args.i)))
  targ_addr_id = obtain_targ_list('%s/funcmap.csv' % (args.i))
  print ('[*] Calculating the distance...')
  all_calldst = calc_all_distance(cg, targ_addr_id)
  with open('%s/calldst.json' % (args.i), 'w') as f:
    json.dump(all_calldst, f)
  print ('[+] Finish the static distance calculation')