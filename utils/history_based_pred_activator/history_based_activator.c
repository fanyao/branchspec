#include "../../include/util.h"
#include "../../include/timingtest.h"

const int pmc1 = 0x00000000; // BR_MISP_EXEC.ALL_CONDITIONAL
uint64_t pmc1_start, pmc1_end;

void main () {
  int limit = 50;

  for (int i = 0; i < limit; i++) {
    /*
     * Count the mispredictions in target branch
     * Here, this sequence will always have either 50% or 100% mispredictions using one-level prediction
     * When history-based prediction is activated, it will start to train multple PHT using history and start to predict correctly
     * 
     * Collect mispredictions here 
     */
    start_1 = (int)readpmc(pmc1);
    if (i % 2) // target branch
      asm("nop");
    end_1 = (int)readpmc(pmc1);

    rdtsc_probe[0][i] = end_1-start_1;
    mfence();
  }
  mfence();

  int error = 0;
  for (int i = 0; i < limit; i++) {
    // Check how many times the target branch is executed in one-level prediction 
    if ( (i > 0) && (rdtsc_probe[0][i])) {
      error++;
    }
  }

  printf("ERROR: %d\n",error);
}