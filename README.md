## FishFuzz: Catch Deeper Bugs by Throwing Larger Nets

<a href="https://hexhive.epfl.ch/paper/23SEC5.pdf" target="_blank"><img src="paper/preview/FishFuzz-preview.png" align="right" width="280"></a>

FishFuzz is an input prioritization strategy that efficiently direct fuzzing towards the promising sanitizer targets. We implement the FishFuzz prototype based on [AFL](https://github.com/google/afl) and [AFL++](https://github.com/AFLplusplus/AFLplusplus/).

For more details, check out our [paper](https://hexhive.epfl.ch/paper/23SEC5.pdf). To cite our work, you can use the following BibTeX entry:

```bibtex
@inproceedings{zheng2023fishfuzz,
  title={FishFuzz: Catch Deeper Bugs by Throwing Larger Nets},
  booktitle = {32st USENIX Security Symposium (USENIX Security 23)},
  publisher = {USENIX Association},
  year={2023},
  author={Zheng, Han and Zhang, Jiayuan and Huang, Yuhang and Ren, Zezhong and Wang, He and Cao, Chunjie and Zhang, Yuqing and Toffalini, Flavio and Payer, Mathias},
}
```

## Published Work

FishFuzz is accepted in USENIX Security Symposium 2023 and will occur with the paper accepted in Winter cycle.

## What is FishFuzz-nonLTO

**Note: This is not the implementation we present in the paper**

* To play FishFuzz with fuzzbench, we find out that some fuzzbench programs didn't work in LTO mode. For compatibility reason, we implement FishFuzz-nonLTO variant.

* Currently we only implement the non-LTO mode for FF_AFL++.

* Make sure the `FUNC_SIZE` in `include/config.h` and `FishFuzzAddressSanitizer.cpp` are coherrent!

## How to play with FishFuzz-nonLTO

```bash

cd $PROJECT_REPO
# create temporary directory and output log files
export TMP_DIR=$PWD/TEMP_xxx
mkdir $TMP_DIR && pushd $TMP_DIR && mkdir cg fid idlog && pushd idlog && touch fid targid && popd && popd
# set env and compile the program to fuzzz
export CC="$PATH_TO_FISHFUZZ/afl-cc -fsanitize=address"
export CXX="$PATH_TO_FISHFUZZ/afl-c++ -fsanitize=address"
./configure --disable-shared && make -j
# then we have all output log (callgraph, function id)
# match the node name to function id, seems the node name in different modules are not duplicated
python3 /Fish++/distance/match_function.py -i $FF_TMP_DIR
# merge all module callgraph
python3 /Fish++/distance/merge_callgraph.py -i $FF_TMP_DIR
# calculate the distance between nodes, therefore we can get the distance between function ids
python3 /Fish++/distance/calculate_distance.py -i $FF_TMP_DIR

# now we're ready to fuzz
TMP_DIR=$FF_TMP_DIR /Fish++/afl-fuzz -i /path/to/in -o /path/to/out -m none -t 1000+ -D -- ./prog @@

```

## Contact

If you have any questions & find any bugs, feel free to contact me via kdsjzh@gmail.com.
