#!/usr/bin/python3

# Written by Zheng Han <kdsjzh@gmail.com>

import os
import json
import argparse


fuzzer_list = ['afl', 'aflpp', 'ffafl', 'ffapp']
benchmark_list = ['catdoc', 'exiv2', 'flvmeta', 'lou_checktable', 'MP4Box', 'nasm', 'nm-new', 'tcpdump', 'tcpprep', 'tiff2pdf', 'gif2tga']

def plot_program_cov(base, prog, timeout):
  with open('%s/%s.cov' % (base, prog)) as f:
    data = json.load(f)
  print ('%12s\t' % prog, end = '')
  for fuzzer in data:
    cov = 0
    for time in data[fuzzer]:
      if int(time) / 3600 / 1000 < timeout:
        cov += len(data[fuzzer][time])
    print ('%12d\t' % cov, end = '')
  print ('')

def plot_all_cov(base, timeout = 24):
  print ('------------------------------------[cov]------------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    plot_program_cov(base, prog, timeout)

def plot_all_vuln(base, timeout):
  print ('------------------------------------[bug]------------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    print ('%12s\t' % prog, end = '')
    with open('%s/%s.san' % (base, prog)) as f:
      data = json.load(f)
      for fuzzer in data:
        vuln = 0
        for time in data[fuzzer]:
          if int(time) / 3600 / 1000 < timeout:
            vuln += 1
        print ('%12d\t' % vuln, end = '')
      print ('')


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to read the results")
  parser.add_argument("-t", type=str, default = 'all', help="type of report, have 3 options: bug, cov and all")
  args = parser.parse_args()
  if args.t == "bug":
    plot_all_vuln(args.b, timeout = 24)
  elif args.t == "cov":
    plot_all_cov(args.b, timeout = 24)
  elif args.t == "all":
    plot_all_cov(args.b, timeout = 24)
    plot_all_vuln(args.b, timeout = 24)
  else :
    print ("[ERROR] unknow type!")
    exit(-1)
  