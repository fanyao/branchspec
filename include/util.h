#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>

uint8_t temp = 0; /* Used so compiler won’t optimize out some of the loops */
uint64_t start = 0, end = 0;
uint64_t start_1 = 0, end_1 = 0;
uint64_t rdtsc_probe[2][1024] = {};

static size_t THRESHOLD = 0;

#ifdef OPENSSL
extern "C" int randomize_pht();
#else
extern int randomize_pht();
#endif



void mfence() {
  /* Utility functions from https://github.com/IAIK/transientfail/ */
  asm volatile("mfence");
}

void flush(void *p) {
  /* Utility functions from https://github.com/IAIK/transientfail/ */
  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

void maccess(void *p) {
  /* Utility functions from https://github.com/IAIK/transientfail/ */
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

uint64_t rdtsc() {
  /* Utility functions from https://github.com/IAIK/transientfail/ */
  uint64_t a, d;
  asm volatile("mfence");
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

// dummy function: Utility to automatically calculate the threshold
unsigned int x1 = 2;
uint8_t x2[2] = {0,1};
void dummy_function(uint8_t x) {
  if (x < x1) {
    if (x2[x]) {
      asm("nop");
    }
  }
}

uint64_t detect_mispred_threshold() {
  uint64_t mispred[64], corrpred[64];

  for (int i = 0; i < 64; i++) {
    #ifdef OPENSSL
    #else
    randomize_pht();
    #endif
    mfence();
    dummy_function(0); dummy_function(0);
    flush(&x1);
    mfence();dummy_function(0);mfence();
    dummy_function(1);
    start_1 = rdtsc();
    dummy_function(1);
    end_1 = rdtsc();
    mispred[i] = end_1 - start_1;
  }
  for (int i = 0; i < 64; i++) {
    #ifdef OPENSSL
    #else
    randomize_pht();
    #endif
    mfence();
    dummy_function(0);
    dummy_function(0);
    flush(&x1);
    mfence();dummy_function(1);mfence();
    dummy_function(1);
    start_1 = rdtsc();
    dummy_function(1);
    end_1 = rdtsc();
    corrpred[i] = end_1 - start_1;
  }

  uint64_t sum = 0, miss_avg = 0, corr_avg = 0;

  for(int i = 0; i < 64; i++)
    sum = sum + mispred[i];
  miss_avg = sum/64;

  sum = 0;
  for(int i = 0; i < 64; i++)
    sum = sum + corrpred[i];
  corr_avg = sum/64;

  uint64_t thresh = corr_avg + (miss_avg-corr_avg)/2;

  return thresh;
}

static inline void nop_16() {
  asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");
  asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");asm("nop");
}

static inline void additional_ops() {
  nop_16();
  nop_16();
  nop_16();
  nop_16();
  nop_16();
  nop_16();
}


// Utilities for two-level predictor based attack

#define FORCE_INLINE __attribute__((always_inline)) inline
#define AT taken_branch(0);
#define AT_START taken_branch(0);
#define AT12 AT AT AT AT AT AT AT AT AT AT AT AT; // 12 taken branch
#define AT100 AT12 AT12 AT12 AT12 AT12 AT12 AT12 AT12 AT AT AT AT;

FORCE_INLINE void taken_branch(int ctrl) {
  if (ctrl)
    asm("nop");
}


int reload_t(void *ptr) {
  /* Utility functions from https://github.com/IAIK/transientfail/ */
  uint64_t start = 0, end = 0;
  start = rdtsc();
  maccess(ptr);
  end = rdtsc();
  mfence();
  return (int)(end - start);
}

int flush_reload_t(void *ptr) {
  /* Utility functions from https://github.com/IAIK/transientfail/ */
  uint64_t start = 0, end = 0;
  start = rdtsc();
  maccess(ptr);
  end = rdtsc();
  flush(ptr);
  mfence();
  return (int)(end - start);
}