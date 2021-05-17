# History-based prediction based BranchSpec-v1 type attack

## Prerequisites

<em>BR_MISP_EXEC.ALL_CONDITIONAL</em> performance counter (for PoC v2). 

This performance counter can be enabled by using the "Test programs for measuring clock cycles and performance monitoring" by Agner Fog (https://www.agner.org/optimize/#testp).

E.g., for Skylake based processor, the BR_MISP_EXEC.ALL_CONDITIONAL counter corresponds with  **Event** 0x89 and **Mask** 0xC1