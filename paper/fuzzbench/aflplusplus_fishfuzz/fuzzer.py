# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Integration code for FishFuzz_AFL fuzzer."""

import json
import os
import shutil
import subprocess
import sys

from fuzzers import utils


def find_files(filename, search_path, mode):
    """Helper function to find path of TEMP, mode 0 for file and 1 for dir"""
    result = ''
    for root, directory, files in os.walk(search_path):
        if mode == 0:
            if filename in files:
                # result.append(os.path.join(root, filename))
                return os.path.join(root, filename)
        else:
            if filename in directory:
                return os.path.join(root, filename)
    return result

def prepare_tmp_files(tmp_dir):
    if not os.path.isdir(tmp_dir) or os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)
    os.mkdir('%s/idlog' % (tmp_dir))
    os.mkdir('%s/cg' % (tmp_dir))
    os.mkdir('%s/fid' % (tmp_dir))
    os.system('touch %s/idlog/fid %s/idlog/targid' % (tmp_dir, tmp_dir))



def prepare_build_environment():
    """Set environment variables used to build targets for AFL-based
    fuzzers."""

    cflags = ['-fsanitize=address']
    utils.append_flags('CFLAGS', cflags)
    utils.append_flags('CXXFLAGS', cflags)

    os.environ['CC'] = '/FishFuzz/afl-cc'
    os.environ['CXX'] = '/FishFuzz/afl-c++'
    os.environ['FUZZER_LIB'] = '/FishFuzz/afl_driver.o'#'/libAFLDriver.a'
    os.environ['TMP_DIR'] = os.environ['OUT'] + '/TEMP'
    os.environ['FF_TMP_DIR'] = os.environ['OUT'] + '/TEMP'
    prepare_tmp_files(os.environ['TMP_DIR'])

    os.environ['AFL_QUIET'] = '1'
    # os.environ['AFL_LLVM_USE_TRACE_PC'] = '1'
    os.environ['AFL_USE_ASAN'] = '1'



def build():
    """Build benchmark."""
    prepare_build_environment()

    #with utils.restore_directory(src), utils.restore_directory(work):
    utils.build_benchmark()

    print('[post_build] Copying afl-fuzz to $OUT directory')
    # Copy out the afl-fuzz binary as a build artifact.
    shutil.copy('/FishFuzz/afl-fuzz', os.environ['OUT'])
    os.environ['AFL_CC'] = 'clang-12'
    os.environ['AFL_CXX'] = 'clang++-12'
    
    tmp_dir_dst = os.environ['OUT'] + '/TEMP'
    print('[post_build] generating distance files')
    # python3 /Fish++/distance/match_function.py -i $FF_TMP_DIR
    # python3 /Fish++/distance/merge_callgraph.py -i $FF_TMP_DIR
    # python3 /Fish++/distance/calculate_distance.py -i $FF_TMP_DIR
    os.system('python3 /FishFuzz/distance/match_function.py -i %s' % (tmp_dir_dst))
    os.system('python3 /FishFuzz/distance/merge_callgraph.py -i %s' % (tmp_dir_dst))
    os.system('python3 /FishFuzz/distance/calculate_distance.py -i %s' % (tmp_dir_dst))

    print('done')


def get_stats(output_corpus, fuzzer_log):  # pylint: disable=unused-argument
    """Gets fuzzer stats for AFL."""
    # Get a dictionary containing the stats AFL reports.
    stats_file = os.path.join(output_corpus, 'fuzzer_stats')
    if not os.path.exists(stats_file):
        print('Can\'t find fuzzer_stats')
        return '{}'
    with open(stats_file, encoding='utf-8') as file_handle:
        stats_file_lines = file_handle.read().splitlines()
    stats_file_dict = {}
    for stats_line in stats_file_lines:
        key, value = stats_line.split(': ')
        stats_file_dict[key.strip()] = value.strip()

    # Report to FuzzBench the stats it accepts.
    stats = {'execs_per_sec': float(stats_file_dict['execs_per_sec'])}
    return json.dumps(stats)


def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with AFL or another AFL-based fuzzer."""
    # Tell AFL to not use its terminal UI so we get usable logs.
    os.environ['AFL_NO_UI'] = '1'
    # Skip AFL's CPU frequency check (fails on Docker).
    os.environ['AFL_SKIP_CPUFREQ'] = '1'
    # No need to bind affinity to one core, Docker enforces 1 core usage.
    os.environ['AFL_NO_AFFINITY'] = '1'
    # AFL will abort on startup if the core pattern sends notifications to
    # external programs. We don't care about this.
    os.environ['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
    # Don't exit when crashes are found. This can happen when corpus from
    # OSS-Fuzz is used.
    os.environ['AFL_SKIP_CRASHES'] = '1'
    # Shuffle the queue
    #os.environ['AFL_SHUFFLE_QUEUE'] = '1'

    # Set temporary dir path
    tmp_dir_src = os.environ['OUT'] + '/TEMP'
    os.environ['TMP_DIR'] = tmp_dir_src

    # AFL needs at least one non-empty seed to start.
    utils.create_seed_file_for_empty_corpus(input_corpus)


def run_afl_fuzz(input_corpus,
                 output_corpus,
                 target_binary,
                 additional_flags=None,
                 hide_output=False):
    """Run afl-fuzz."""
    # Spawn the afl fuzzing process.

    os.environ['AFL_IGNORE_UNKNOWN_ENVS'] = '1'
    os.environ['AFL_FAST_CAL'] = '1'
    os.environ['AFL_NO_WARN_INSTABILITY'] = '1'
    os.environ['AFL_DISABLE_TRIM'] = '1'
    os.environ['AFL_CMPLOG_ONLY_NEW'] = '1'
    os.environ['AFL_MAP_SIZE'] = '2621440'


    print('[run_afl_fuzz] Running target with afl-fuzz')
    command = [
        './afl-fuzz',
        '-i',
        input_corpus,
        '-o',
        output_corpus,
        '-t',
        '1000+',  # Use same default 1 sec timeout, but add '+' to skip hangs.
    ]

    if additional_flags:
        command.extend(additional_flags)

    # dictionary_path = utils.get_dictionary_path(target_binary)
    # if dictionary_path:
    #     command.extend(['-x', dictionary_path])
    if os.path.exists('./afl++.dict'):
        flags += ['-x', './afl++.dict']

    #command += ['-x', './afl++.dict']
    #command += ['-c', cmplog_target_binary]

    command += [
        '--',
        target_binary,
        # Pass INT_MAX to afl the maximize the number of persistent loops it
        # performs.
        '2147483647'
    ]

    print('[run_afl_fuzz] Running command: ' + ' '.join(command))
    output_stream = subprocess.DEVNULL if hide_output else None
    subprocess.check_call(command, stdout=output_stream, stderr=output_stream)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run afl-fuzz on target."""

    prepare_fuzz_environment(input_corpus)

    run_afl_fuzz(input_corpus, output_corpus, target_binary)