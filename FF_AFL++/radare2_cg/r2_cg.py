#!/usr/bin/python3

import r2pipe
import json
import re
import argparse


__black_func_list = [
  '__asan',
  '__ubsan',
  '__lsan',
  '__sanitizer'
]

def black_list_func(name):
  # if not name.startswith('dbg.'):
  #   return 1
  for __black_func in __black_func_list:
    if name.startswith('dbg.%s' % (__black_func)):
      return 1
  return 0

def dis_one_func(r2p, faddr, fname):
  # pd for disassemble, f for function, j for json format
  # considering of :: and (), we use address instead
  json_func_str = r2p.cmd('pdfj @%s' % (faddr))
  if json_func_str == '':
    return ''
  f_inst_obj = json.loads(json_func_str)
  for inst_idx in range(len(f_inst_obj['ops'])):
    inst = f_inst_obj['ops'][inst_idx]
    # usually the operations will be 1. mov rax, obj.__afl_fish_map 2. mov rax, qword [rax] 3. mov byte [rax + id], 1
    # however, in some cases, there might be other operations
    if inst['disasm'].find('__afl_fish_map') != -1:
      for store_idx in range(inst_idx + 2, len(f_inst_obj['ops'])):
        store_inst = f_inst_obj['ops'][store_idx]
        store_esil = store_inst['esil'].split(',')
        if len(store_esil) == 5:
          offset_str = store_esil[1]
          return offset_str
      # store_inst = f_inst_obj['ops'][inst_idx + 2]
      # offset_str = store_inst['esil'].split(',')[1]
      # print ('[LOG] for function @%s, we find function id %s' % (fname, offset_str))
      # return offset_str
  return ''


def obtain_func_list(r2p, output_dir):
  # af for analyze function, l for list, j for json format
  fo = open('%s/funcmap.csv' % (output_dir), 'w')
  all_func_obj = json.loads(r2p.cmd('aflj'))
  for f_obj in all_func_obj:
    if not black_list_func(f_obj['name']):
      offset_str = dis_one_func(r2p, hex(f_obj['offset']), f_obj['name'])
      if offset_str != '':
        # print ('[LOG] Function name @%s, id %s' % (f_obj['name'], offset_str))
        fo.write('%s,%s,%s\n' % (f_obj['name'], hex(f_obj['offset']), offset_str))
  fo.close()

def generate_cg(r2p, output_dir):
  r2p.cmd('agCd > %s/callgraph.dot' % output_dir)

def main():
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-b', type=str, required=True, help="Path to binary that requires cg distance calc.")
  parser.add_argument ('-o', type=str, required=True, help="Path to output dir containing distance for each node.")
  args = parser.parse_args ()
  print ('[*] Loading and analyzing the binary...')
  r2p = r2pipe.open(args.b)
  r2p.cmd('aaa')
  print ('[*] Calculating the function id list...')
  obtain_func_list(r2p, args.o)
  print ('[*] Generating the callgraph...')
  generate_cg(r2p, args.o)
  print ('[+] Finish the radare2 analysis')

if __name__ == "__main__":
  main()