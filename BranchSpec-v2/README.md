# BranchSpec-v2 gadget search tool

## Prerequisites

Python 2 with distorm3, pyelftools and tqdm installed. 

```bash
    pip install --user distorm3
    pip install --user pyelftools
    pip install --user tqdm
```

<em>openssl_gadgets.dat</em>: This file contains list of BranchSpectre-v2 type transmitter gadgets found in OpenSSL v1.1.1b (libcrypt.a).

<em>common_libraries_gadgets.dat</em>: This file contains list of BranchSpectre-v2 type transmitter gadgets found in other common libraries.