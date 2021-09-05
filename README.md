# BranchSpec: Leaking Sensitive Information through Speculative Branch Instruction Executions

This repository contains proof-of-concept of information leakage attacks exploiting branch instruction executions in speculative path. More details about BranchSpec-v1 based one-level prediction in this work can be found in our [paper](http://fan-yao.com/paper/2020_ICCD_branchspec.pdf). Our work can be cited using the following information:

```bibtex
@inproceedings{branchspec2020,
  title={{BranchSpec: Information Leakage Attacks Exploiting Speculative Branch Instruction Executions}},
  author={Chowdhuryy, Md Hafizul Islam and Liu, Hang and Yao, Fan},
  booktitle={IEEE International Conference on Computer Design (ICCD)},
  year={2020}
}
```

## Tested systems

- Intel(R) Xeon(R) Gold 6242 (Family: Cascade Lake, Microcode: 0x5002f01)
- Intel(R) Core(TM) i5-9500 (Family: Coffee Lake, Microcode: 0xd6) 
- Intel(R) Core(TM) i7-6700 (Family: Skylake, Microcode: 0xdc)

## Environment

- **Operating System:** Ubuntu 18.04.5 LTS
- **Kernel:** 5.4.0-42-generic
- **GCC:** 7.5.0

## Variants

This repository contains PoC code for both one-level prediction and history-based prediction attacks using BranchSpec-v1, gadget search tool for BranchSpec-v2 and utilites to determine condition for GHR flushing in history-based prediction and activation condition of history-based prediction.

## Contents:
- BranchSpec-v1
    - one_level_prediction
        - PoC v1: Nested if conditional, single-threaded
        - PoC v2: Nested for loop, multi-threaded
    - history_based_prediction
        - PoC v1: Nested if conditional, multi-threaded
        - PoC v2: Nested if conditional, calibration
- BranchSpec-v2
    - Gadget search tool 
- Utils
    - GHR Flush: Determine GHR flush length
    - History-based prediction activation: Determine activation criterion for history-based prediction

## Building

This project uses GNU Make, GCC and nasm to compile. On Ubuntu, you can install them using:

```bash
sudo apt-get install build-essential
sudo apt-get install nasm
```

Steps to reproduce the vulnerability:

```bash
# Clone the repository
git clone https://github.com/fanyao/branchspec

# cd into the source directory
cd branchspec/one_level_prediction

# build the binaries
make all

# run the binaries using taskset to pin into one core
taskset 0x02 ./poc_v1
```

Note: Change the <code>THRESHOLD</code> in line 36 of the source file (i.e., BranchSpec-v1>one_level_prediction>poc_v1.c) according to your system.

## Running the PoC

```bash
taskset 0x04 ./poc_v1
```
<details>
    <summary> Example output (<i>click to expand</i>)</summary>
    
```
Transmitting secret...
Secret value, secret[0]: 0; Inferred: 0; Latency: 145
Secret value, secret[1]: 1; Inferred: 1; Latency: 129
Secret value, secret[2]: 0; Inferred: 0; Latency: 149
Secret value, secret[3]: 0; Inferred: 0; Latency: 145
Secret value, secret[4]: 1; Inferred: 1; Latency: 125
Secret value, secret[5]: 0; Inferred: 0; Latency: 145
Secret value, secret[6]: 1; Inferred: 1; Latency: 131
Secret value, secret[7]: 1; Inferred: 1; Latency: 129
Secret value, secret[8]: 1; Inferred: 1; Latency: 125
Secret value, secret[9]: 0; Inferred: 0; Latency: 148
Secret value, secret[10]: 1; Inferred: 1; Latency: 127
Secret value, secret[11]: 1; Inferred: 1; Latency: 129
Secret value, secret[12]: 0; Inferred: 0; Latency: 147
Secret value, secret[13]: 1; Inferred: 1; Latency: 127
Secret value, secret[14]: 1; Inferred: 1; Latency: 127
Secret value, secret[15]: 0; Inferred: 0; Latency: 147
Secret value, secret[16]: 1; Inferred: 1; Latency: 127
Secret value, secret[17]: 0; Inferred: 0; Latency: 147
Secret value, secret[18]: 0; Inferred: 0; Latency: 147
Secret value, secret[19]: 1; Inferred: 1; Latency: 127
Secret value, secret[20]: 0; Inferred: 0; Latency: 145
Secret value, secret[21]: 0; Inferred: 0; Latency: 147
Secret value, secret[22]: 0; Inferred: 0; Latency: 147
Secret value, secret[23]: 1; Inferred: 1; Latency: 129
Secret value, secret[24]: 1; Inferred: 1; Latency: 127
Secret value, secret[25]: 1; Inferred: 1; Latency: 127
Secret value, secret[26]: 1; Inferred: 1; Latency: 127
Secret value, secret[27]: 1; Inferred: 1; Latency: 127
Secret value, secret[28]: 1; Inferred: 1; Latency: 129
Secret value, secret[29]: 1; Inferred: 1; Latency: 129
Secret value, secret[30]: 1; Inferred: 1; Latency: 125
Secret value, secret[31]: 1; Inferred: 1; Latency: 129
Secret value, secret[32]: 0; Inferred: 0; Latency: 147
Secret value, secret[33]: 1; Inferred: 1; Latency: 127
Secret value, secret[34]: 0; Inferred: 0; Latency: 143
Secret value, secret[35]: 1; Inferred: 1; Latency: 129
Secret value, secret[36]: 0; Inferred: 0; Latency: 143
Secret value, secret[37]: 1; Inferred: 1; Latency: 131
Secret value, secret[38]: 1; Inferred: 1; Latency: 125
Secret value, secret[39]: 1; Inferred: 1; Latency: 127
Secret value, secret[40]: 0; Inferred: 0; Latency: 147
Secret value, secret[41]: 1; Inferred: 1; Latency: 127
Secret value, secret[42]: 0; Inferred: 0; Latency: 147
Secret value, secret[43]: 1; Inferred: 1; Latency: 129
Secret value, secret[44]: 0; Inferred: 0; Latency: 149
Secret value, secret[45]: 1; Inferred: 1; Latency: 125
Secret value, secret[46]: 0; Inferred: 0; Latency: 145
Secret value, secret[47]: 1; Inferred: 1; Latency: 127
Secret value, secret[48]: 0; Inferred: 0; Latency: 145
Secret value, secret[49]: 1; Inferred: 1; Latency: 127
Secret value, secret[50]: 0; Inferred: 0; Latency: 145
Secret value, secret[51]: 0; Inferred: 0; Latency: 147
Secret value, secret[52]: 1; Inferred: 1; Latency: 125
Secret value, secret[53]: 1; Inferred: 1; Latency: 129
Secret value, secret[54]: 0; Inferred: 0; Latency: 147
Secret value, secret[55]: 1; Inferred: 1; Latency: 127
Secret value, secret[56]: 1; Inferred: 1; Latency: 125
Secret value, secret[57]: 0; Inferred: 0; Latency: 147
Secret value, secret[58]: 1; Inferred: 1; Latency: 129
Secret value, secret[59]: 0; Inferred: 0; Latency: 147
Secret value, secret[60]: 1; Inferred: 1; Latency: 125
Secret value, secret[61]: 0; Inferred: 0; Latency: 148
Secret value, secret[62]: 0; Inferred: 0; Latency: 143
Secret value, secret[63]: 1; Inferred: 1; Latency: 127
Secret value, secret[64]: 0; Inferred: 0; Latency: 147
Secret value, secret[65]: 1; Inferred: 1; Latency: 129
Secret value, secret[66]: 0; Inferred: 0; Latency: 148
Secret value, secret[67]: 1; Inferred: 1; Latency: 125
Secret value, secret[68]: 1; Inferred: 1; Latency: 127
Secret value, secret[69]: 0; Inferred: 0; Latency: 147
Secret value, secret[70]: 1; Inferred: 1; Latency: 129
Secret value, secret[71]: 0; Inferred: 0; Latency: 149
Secret value, secret[72]: 0; Inferred: 0; Latency: 146
Secret value, secret[73]: 1; Inferred: 1; Latency: 127
Secret value, secret[74]: 1; Inferred: 1; Latency: 125
Secret value, secret[75]: 0; Inferred: 0; Latency: 146
Secret value, secret[76]: 1; Inferred: 1; Latency: 129
Secret value, secret[77]: 0; Inferred: 0; Latency: 146
Secret value, secret[78]: 1; Inferred: 1; Latency: 129
Secret value, secret[79]: 0; Inferred: 0; Latency: 146
Secret value, secret[80]: 0; Inferred: 0; Latency: 149
Secret value, secret[81]: 0; Inferred: 0; Latency: 147
Secret value, secret[82]: 0; Inferred: 0; Latency: 147
Secret value, secret[83]: 0; Inferred: 0; Latency: 147
Secret value, secret[84]: 1; Inferred: 1; Latency: 131
Secret value, secret[85]: 0; Inferred: 0; Latency: 146
Secret value, secret[86]: 1; Inferred: 1; Latency: 129
Secret value, secret[87]: 0; Inferred: 0; Latency: 147
Secret value, secret[88]: 0; Inferred: 0; Latency: 147
Secret value, secret[89]: 0; Inferred: 0; Latency: 147
Secret value, secret[90]: 0; Inferred: 0; Latency: 145
Secret value, secret[91]: 1; Inferred: 1; Latency: 129
Secret value, secret[92]: 1; Inferred: 1; Latency: 127
Secret value, secret[93]: 1; Inferred: 1; Latency: 127
Secret value, secret[94]: 0; Inferred: 0; Latency: 147
Secret value, secret[95]: 0; Inferred: 0; Latency: 147
Secret value, secret[96]: 0; Inferred: 0; Latency: 147
Secret value, secret[97]: 1; Inferred: 1; Latency: 127
Secret value, secret[98]: 1; Inferred: 1; Latency: 127
Secret value, secret[99]: 1; Inferred: 1; Latency: 129
Total bit sent: 100, Total Error: 0, Threshold: 138
```
</details>

