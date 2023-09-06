#!/usr/bin/env python3
'''
  Copied from https://github.com/aflgo/aflgo/blob/master/scripts/merge_callgraphs.py
'''

import argparse
import os
import networkx as nx


__black_module_list = [
  'conftest',
  'CMakeCCompilerId',
  'CMakeCXXCompilerId',
]

__prefix_name = {
  'fid': '.fid.txt',
  'cg' : '.callgraph.dot',
  'node' : '.node2id.txt'
}

def __is_black_listed_module(module_name):
  for __black_module in __black_module_list:
    if module_name.startswith(__black_module):
      return 1
  return 0

def remove_prefix(file_name, type_prefix):
  module_name = file_name[: - len(__prefix_name[type_prefix])]
  if __is_black_listed_module(module_name):
    return ''
  return module_name

def __is_valid_nodename(node_name):
  if node_name.startswith('Node0x'):
    return 1
  return 0

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', required=True, help="Path to whole Temporary directory.")

  args = parser.parse_args()

  G = nx.DiGraph()
  for cg in os.listdir('%s/cg' % (args.i)):
    module_name = remove_prefix(cg, 'cg')
    if not module_name:
      continue
    print ("[*] Updating callgraph from %s..." % (module_name))
    G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot('%s/cg/%s' % (args.i, cg))))

  node_list = list(G.nodes().keys())
  for node_name in node_list:
    if not __is_valid_nodename(node_name):
      G.remove_node(node_name)
  
  with open('%s/callgraph.dot' % (args.i), 'w') as f:
    nx.drawing.nx_pydot.write_dot(G, f)
  
  print ("[+] Done, generate whole package callgraph.dot")

# Main function
if __name__ == '__main__':
  main()