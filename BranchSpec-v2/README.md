# BranchSpec-v2 gadget search tool

## Prerequisites

Python 2 with distorm3, pyelftools and tqdm installed. 

```bash
    pip install --user distorm3
    pip install --user pyelftools
    pip install --user tqdm
```

Some of the snippets of this search tool are taken from https://github.com/HexHive/SMoTherSpectre


<em>openssl_gadgets.dat</em>: This file contains list of BranchSpectre-v2 type transmitter gadgets found in OpenSSL v1.1.1b (libcrypt.a). Note that each gadgets in this file can leak one specific bit of first byte referenced by register <em>RDX</em>.