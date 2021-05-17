# One-level prediction based BranchSpec-v1 type attack

## Variants

This repository contains two PoCs, each of which exploits a different code gadget.

#### Variant 1: **poc_v1**

Nested speculation followed by <code>if</code> branch
```c
if (x < array_size) {
    if (array[x]) {
        <some_function>
    }
}
```

#### Variant 2: **poc_v2**

Nested speculation followed by <code>for</code> loop
```c
for (int i = x; i < array_size; i++) {
    if (array[i]) {
        <some_function>
    }
    <some_additional_functions>
}
```


## Building


```bash
# build the binaries
make all

# run the binaries using taskset to pin into one core
taskset 0x02 ./poc_v1
```

Note: Change the <code>THRESHOLD</code> in line 36 of the source file (i.e., poc_v1.c/poc_v2.c) according to your system.
