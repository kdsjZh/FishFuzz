FROM ubuntu:20.04

# for binutils & llvm-15 dependencies
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC \
    apt install git gcc g++ make cmake wget \
        libgmp-dev libmpfr-dev texinfo bison python3 -y 

# build clang-15 with gold plugin
RUN apt install -y lsb-release wget software-properties-common

COPY FishFuzz/FF_AFL++ /Fish++

# build clang-15
RUN mkdir -p /build && \
    git clone \
        https://github.com/llvm/llvm-project /llvm && \
    cd /llvm/ && git checkout bf7f8d6fa6f460bf0a16ffec319cd71592216bf4 && \
    git apply /Fish++/asan_patch/llvm-15.0/llvm-15-asan.diff && \
    cp /Fish++/asan_patch/llvm-15.0/FishFuzzAddressSanitizer.cpp llvm/lib/Transforms/Instrumentation/ && \
    cd /llvm/ && mkdir build && cd build &&\
    CFLAGS="" CXXFLAGS="" CC=gcc CXX=g++ \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DLLVM_ENABLE_PROJECTS="compiler-rt;clang" \
          -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" ../llvm && \
    make -j$(nproc) 

ENV PATH="/llvm/build/bin:${PATH}"
ENV LD_LIBRARY_PATH="/llvm/build/lib/x86_64-unknown-linux-gnu/"


# for fishfuzz dependencies
RUN apt-get update && \
    apt-get install libboost-all-dev libjsoncpp-dev libgraphviz-dev \
    pkg-config libglib2.0-dev gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev -y

RUN apt install python3-pip -y && \
    pip3 install networkx pydot r2pipe

# # COPY Fish++ /Fish++ 
# RUN git clone https://github.com/HexHive/FishFuzz /ff_repo && \
#     mv /ff_repo/FF_AFL++ /Fish++ && rm -r /ff_repo

RUN cd /Fish++/ && \
    wget https://github.com/AFLplusplus/AFLplusplus/raw/127c345161769c513275fed9d64de12536ee979d/instrumentation/SanitizerCoveragePCGUARD.so.cc instrumentation && \
    NO_NYX=1 make source-only && chmod +x scripts/*.py 

