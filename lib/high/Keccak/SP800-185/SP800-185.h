/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _SP800_185_h_
#define _SP800_185_h_

#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#ifdef XKCP_has_KeccakP1600

#include <stddef.h>
#include <stdint.h>
#include "align.h"
#include "KeccakSponge.h"
#include "Phases.h"

#ifndef _Keccak_BitTypes_
#define _Keccak_BitTypes_
typedef uint8_t BitSequence;

typedef size_t BitLength;
#endif

typedef struct {
    KeccakWidth1600_SpongeInstance  sponge;
    BitLength                       fixedOutputLength;
    unsigned int                    lastByteBitLen;
    BitSequence                     lastByteValue;
    int                             emptyNameCustom;
    KCP_Phases                      phase;
} cSHAKE_Instance;

// Global variables for KMAC256 calculation over DPI
#define KMAC_OUTPUT_DATA_BYTE_LEN  32
#define KMAC_INPUT_DATA_BYTE_LEN   65
#define KMAC_KEY_BYTE_LEN          32
// Output array
char          kmac_256_out_msg[KMAC_OUTPUT_DATA_BYTE_LEN];
// Input array
char          kmac_256_data_in[KMAC_INPUT_DATA_BYTE_LEN];
// Key
char          kmac_256_key[KMAC_KEY_BYTE_LEN];
// Input array counter
int unsigned  kmac_input_bytes_cnt;
// KMAC256 return value
int           kmac_256_result;


/** cSHAKE128 function, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  input           Pointer to the input message (X).
  * @param  inputBitLen     The length of the input message in bits.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The desired number of output bits (L).
  * @param  name            Pointer to the function name string (N).
  * @param  nameBitLen      The length of the function name in bits.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE128( const BitSequence *input, BitLength inputBitLen, BitSequence *output, BitLength outputBitLen, const BitSequence *name, BitLength nameBitLen, const BitSequence *customization, BitLength customBitLen );

/**
  * Function to initialize the cSHAKE128 instance used in sequential hashing mode.
  * @param  cskInstance     Pointer to the hash instance to be initialized.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  name            Pointer to the function name string (N).
  * @param  nameBitLen      The length of the function name in bits.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE128_Initialize(cSHAKE_Instance *cskInstance, BitLength outputBitLen, const BitSequence *name, BitLength nameBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be absorbed.
  * @param  cskInstance     Pointer to the hash instance initialized by cSHAKE128_Initialize().
  * @param  input           Pointer to the input data.
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only the last update call can input a partial byte, other calls must have a length multiple of 8.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE128_Update(cSHAKE_Instance *cskInstance, const BitSequence *input, BitLength inputBitLen);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling cSHAKE128_Initialize().
  * @param  cskInstance     Pointer to the hash instance initialized by cSHAKE128_Initialize().
  *                         If @a outputBitLen was not 0 in the call to cSHAKE128_Initialize(), the number of
  *                         output bits is equal to @a outputBitLen.
  *                         If @a outputBitLen was 0 in the call to cSHAKE128_Initialize(), the output bits
  *                         must be extracted using the cSHAKE128_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE128_Final(cSHAKE_Instance *cskInstance, BitSequence *output);

 /**
  * Function to squeeze output data.
  * @param  cskInstance     Pointer to the hash instance initialized by cSHAKE128_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    cSHAKE128_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE128_Squeeze(cSHAKE_Instance *cskInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

/** cSHAKE256 function, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  input           Pointer to the input message (X).
  * @param  inputBitLen     The length of the input message in bits.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The desired number of output bits (L).
  * @param  name            Pointer to the function name string (N).
  * @param  nameBitLen      The length of the function name in bits.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE256( const BitSequence *input, BitLength inputBitLen, BitSequence *output, BitLength outputBitLen, const BitSequence *name, BitLength nameBitLen, const BitSequence *customization, BitLength customBitLen );

/**
  * Function to initialize the cSHAKE256 instance used in sequential hashing mode.
  * @param  cskInstance     Pointer to the hash instance to be initialized.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  name            Pointer to the function name string (N).
  * @param  nameBitLen      The length of the function name in bits.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE256_Initialize(cSHAKE_Instance *cskInstance, BitLength outputBitLen, const BitSequence *name, BitLength nameBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be absorbed.
  * @param  cskInstance     Pointer to the hash instance initialized by cSHAKE256_Initialize().
  * @param  input           Pointer to the input data.
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only the last update call can input a partial byte, other calls must have a length multiple of 8.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE256_Update(cSHAKE_Instance *cskInstance, const BitSequence *input, BitLength inputBitLen);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling cSHAKE256_Initialize().
  * @param  cskInstance     Pointer to the hash instance initialized by cSHAKE256_Initialize().
  *                         If @a outputBitLen was not 0 in the call to cSHAKE256_Initialize(), the number of
  *                         output bits is equal to @a outputBitLen.
  *                         If @a outputBitLen was 0 in the call to cSHAKE256_Initialize(), the output bits
  *                         must be extracted using the cSHAKE256_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE256_Final(cSHAKE_Instance *cskInstance, BitSequence *output);

 /**
  * Function to squeeze output data.
  * @param  cskInstance     Pointer to the hash instance initialized by cSHAKE256_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    cSHAKE256_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int cSHAKE256_Squeeze(cSHAKE_Instance *cskInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

typedef struct {
    cSHAKE_Instance csi;
    BitLength outputBitLen;
} KMAC_Instance;

/** KMAC128 function, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  key             Pointer to the key (K).
  * @param  keyBitLen       The length of the key in bits.
  * @param  input           Pointer to the input message (X).
  * @param  inputBitLen     The length of the input message in bits.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The desired number of output bits (L).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC128(const BitSequence *key, BitLength keyBitLen, const BitSequence *input, BitLength inputBitLen,
        BitSequence *output, BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to initialize the KMAC128 instance used in sequential MACing mode.
  * @param  kmInstance      Pointer to the instance to be initialized.
  * @param  key             Pointer to the key (K).
  * @param  keyBitLen       The length of the key in bits.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC128_Initialize(KMAC_Instance *kmkInstance, const BitSequence *key, BitLength keyBitLen, BitLength outputBitLen,
        const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be MACed.
  * @param  kmInstance      Pointer to the instance initialized by KMAC128_Initialize().
  * @param  input           Pointer to the input data.
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC128_Update(KMAC_Instance *kmkInstance, const BitSequence *input, BitLength inputBitLen);

/**
  * Function to call after all input data have been input and to get
  * output bits if the length was specified when calling KMAC128_Initialize().
  * @param  kmInstance      Pointer to the instance initialized by KMAC128_Initialize().
  *                         If @a outputBitLen was not 0 in the call to KMAC128_Initialize(), the number of
  *                         output bits is equal to @a outputBitLen.
  *                         If @a outputBitLen was 0 in the call to KMAC128_Initialize(), the output bits
  *                         must be extracted using the KMAC128_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC128_Final(KMAC_Instance *kmkInstance, BitSequence *output);

 /**
  * Function to squeeze output data.
  * @param  kmInstance      Pointer to the instance initialized by KMAC128_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    KMAC128_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC128_Squeeze(KMAC_Instance *kmkInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

/** KMAC256 function, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  key             Pointer to the key (K).
  * @param  keyBitLen       The length of the key in bits.
  * @param  input           Pointer to the input message (X).
  * @param  inputBitLen     The length of the input message in bits.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The desired number of output bits (L).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC256(const BitSequence *key, BitLength keyBitLen, const BitSequence *input, BitLength inputBitLen,
        BitSequence *output, BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);


/** Prints string as hexadecimal number
  * @param  str             String to print
  */
void pshex(const unsigned char* str)
{
    const unsigned char* str_i = str;

    for ( ; *str_i != '\0'; ++str_i )
    {
        printf("%02x ", *str_i);
    }
}

/** Stores KMAC Key byte
  * @param  key_byte           Key byte value
  * @param  byte_index         Key byte index
  */
int SET_KMAC_KEY_BYTE(char key_byte, unsigned int byte_index)
{
  kmac_256_key[byte_index] = key_byte;
  return 0;
}

/** Stores KMAC input data byte
  * @param  data_byte          Input data byte value
  * @param  byte_index         Data byte index
  */
int SET_KMAC_DATA_IN_BYTE(char data_byte, unsigned int byte_index)
{
  kmac_256_data_in[byte_index] = data_byte;
  kmac_input_bytes_cnt         = byte_index + 1;
  return 0;
}

/** Return KMAC output data byte
  * @param  byte_index         Data byte index
  */
char GET_KMAC_DATA_OUT_BYTE(unsigned int byte_index)
{
  return kmac_256_out_msg[byte_index];
}

/** KMAC256SV function, wrapper callable from System Verilog via DPI.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC256SV(void)
{
    const BitSequence     *customization  = (const BitSequence *)"My Tagged Application";
    unsigned int           custom_bit_len = strlen((const char *)customization) * 8;

    // Clear output buffer
    memset(kmac_256_out_msg, 0, sizeof(char)*KMAC_OUTPUT_DATA_BYTE_LEN);

    printf("XKCP:   KMAC256SV called with arguments:\n");

    printf("XKCP:     Key = ");
    pshex(kmac_256_key);
    printf(" ( %s ) \n", kmac_256_key);

    printf("XKCP:     Key bit length = %d\n", KMAC_KEY_BYTE_LEN*8);

    printf("XKCP:     Message input = ");
    pshex(kmac_256_data_in);
    printf(" ( %s )\n", kmac_256_data_in);

    printf("XKCP:     Input bit length = %d\n", kmac_input_bytes_cnt*8);
    printf("XKCP:     Output bit length = %d\n", KMAC_OUTPUT_DATA_BYTE_LEN*8);

    printf("XKCP:     Customization string = ");
    pshex(customization);
    printf(" ( %s )\n", customization);

    printf("XKCP:     Customization string bit length = %d\n", custom_bit_len);

    printf("XKCP: Running KMAC256 calculation...\n");

    kmac_256_result = KMAC256(
      (const BitSequence *) kmac_256_key,
      (BitLength) KMAC_KEY_BYTE_LEN*8,
      (const BitSequence *) kmac_256_data_in,
      (BitLength) kmac_input_bytes_cnt*8,
      kmac_256_out_msg,
      (BitLength) KMAC_OUTPUT_DATA_BYTE_LEN*8,
      (const BitSequence *) customization,
      (BitLength) custom_bit_len
    );

    printf("XKCP: Results of KMAC256 calculation: \n");
    printf("XKCP:     Return value = %d\n", kmac_256_result);
    printf("XKCP:     Output data = ");
    pshex(kmac_256_out_msg);
    printf(" ( %s )\n", kmac_256_out_msg);

    printf("\n");

    return kmac_256_result;
}

/** @return Output message from previous KMAC256 computation
  */
char* KMAC256SV_GET_OUT_MSG(void)
{
    return kmac_256_out_msg;
}

/**
  * Function to initialize the KMAC256 instance used in sequential MACing mode.
  * @param  kmInstance      Pointer to the instance to be initialized.
  * @param  key             Pointer to the key (K).
  * @param  keyBitLen       The length of the key in bits.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC256_Initialize(KMAC_Instance *kmkInstance, const BitSequence *key, BitLength keyBitLen, BitLength outputBitLen,
        const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be MACed.
  * @param  kmInstance      Pointer to the instance initialized by KMAC256_Initialize().
  * @param  input           Pointer to the input data.
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC256_Update(KMAC_Instance *kmkInstance, const BitSequence *input, BitLength inputBitLen);

/**
  * Function to call after all input data have been input and to get
  * output bits if the length was specified when calling KMAC256_Initialize().
  * @param  kmInstance      Pointer to the instance initialized by KMAC256_Initialize().
  *                         If @a outputBitLen was not 0 in the call to KMAC256_Initialize(), the number of
  *                         output bits is equal to @a outputBitLen.
  *                         If @a outputBitLen was 0 in the call to KMAC256_Initialize(), the output bits
  *                         must be extracted using the KMAC256_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC256_Final(KMAC_Instance *kmkInstance, BitSequence *output);

 /**
  * Function to squeeze output data.
  * @param  kmInstance      Pointer to the instance initialized by KMAC256_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    KMAC256_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int KMAC256_Squeeze(KMAC_Instance *kmkInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

typedef struct {
    KeccakWidth1600_SpongeInstance queueNode;
    KeccakWidth1600_SpongeInstance finalNode;
    size_t fixedOutputLength;
    size_t blockLen;
    size_t queueAbsorbedLen;
    size_t totalInputSize;
    KCP_Phases phase;
} ParallelHash_Instance;

/** Parallel hash function ParallelHash128, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  input           Pointer to the input message (X).
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  blockByteLen    Block size (B) in bytes, must be a power of 2.
  *                         The minimum value is 8 in this implementation.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The desired number of output bits (L).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash128( const BitSequence *input, BitLength inputBitLen, size_t blockByteLen,
        BitSequence *output, BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to initialize the parallel hash function ParallelHash128 instance used in sequential hashing mode.
  * @param  ParallelHashInstance     Pointer to the hash instance to be initialized.
  * @param  blockByteLen    Block size (B) in bytes, must be a power of 2.
  *                         The minimum value is 8 in this implementation.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash128_Initialize(ParallelHash_Instance *ParallelHashInstance, size_t blockByteLen,
        BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be absorbed.
  * @param  ParallelHashInstance     Pointer to the hash instance initialized by ParallelHash128_Initialize().
  * @param  input           Pointer to the input data (X).
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash128_Update(ParallelHash_Instance *ParallelHashInstance, const BitSequence *input, BitLength inputBitLen);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling ParallelHash128_Initialize().
  * @param  ParallelHashInstance     Pointer to the hash instance initialized by ParallelHash128_Initialize().
  * If @a outputBitLen was not 0 in the call to ParallelHash128_Initialize(), the number of
  *     output bits is equal to @a outputBitLen.
  * If @a outputBitLen was 0 in the call to ParallelHash128_Initialize(), the output bits
  *     must be extracted using the ParallelHash128_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash128_Final(ParallelHash_Instance *ParallelHashInstance, BitSequence * output);

 /**
  * Function to squeeze output data.
  * @param  ParallelHashInstance    Pointer to the hash instance initialized by ParallelHash128_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    ParallelHash128_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash128_Squeeze(ParallelHash_Instance *ParallelHashInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

/** Parallel hash function ParallelHash256, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  input           Pointer to the input message (X).
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @param  blockByteLen    Block size (B) in bytes, must be a power of 2.
  *                         The minimum value is 8 in this implementation.
  * @param  output          Pointer to the output buffer.
  * @param  outputBitLen    The desired number of output bits (L).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash256( const BitSequence *input, BitLength inputBitLen, size_t blockByteLen,
        BitSequence *output, BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to initialize the parallel hash function ParallelHash256 instance used in sequential hashing mode.
  * @param  ParallelHashInstance     Pointer to the hash instance to be initialized.
  * @param  blockByteLen    Block size (B) in bytes, must be a power of 2.
  *                         The minimum value is 8 in this implementation.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash256_Initialize(ParallelHash_Instance *ParallelHashInstance, size_t blockByteLen,
        BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be absorbed.
  * @param  ParallelHashInstance     Pointer to the hash instance initialized by ParallelHash256_Initialize().
  * @param  input           Pointer to the input data (X).
  * @param  inputBitLen     The number of input bits provided in the input data.
  *                         Only full bytes are supported, length must be a multiple of 8.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash256_Update(ParallelHash_Instance *ParallelHashInstance, const BitSequence *input, BitLength inputBitLen);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling ParallelHash256_Initialize().
  * @param  ParallelHashInstance     Pointer to the hash instance initialized by ParallelHash256_Initialize().
  * If @a outputBitLen was not 0 in the call to ParallelHash256_Initialize(), the number of
  *     output bits is equal to @a outputBitLen.
  * If @a outputBitLen was 0 in the call to ParallelHash256_Initialize(), the output bits
  *     must be extracted using the ParallelHash256_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash256_Final(ParallelHash_Instance *ParallelHashInstance, BitSequence * output);

 /**
  * Function to squeeze output data.
  * @param  ParallelHashInstance    Pointer to the hash instance initialized by ParallelHash256_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    ParallelHash256_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int ParallelHash256_Squeeze(ParallelHash_Instance *ParallelHashInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

typedef struct {
    cSHAKE_Instance csi;
    BitLength outputBitLen;
} TupleHash_Instance;

typedef struct {
    /** Pointer to the tuple element data (Xn). */
    const BitSequence *input;

    /** The number of input bits provided in this tuple element.
     *  Only full bytes are supported, length must be a multiple of 8.
     */
    BitLength inputBitLen;
} TupleElement;

/** Tuple hash function TupleHash128, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  tuple            Pointer to an array of tuple elements (X).
  * @param  numberOfElements The number of tuple elements provided in the input data.
  * @param  output           Pointer to the output buffer.
  * @param  outputBitLen     The desired number of output bits (L).
  * @param  customization    Pointer to the customization string (S).
  * @param  customBitLen     The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash128( const TupleElement *tuple, size_t numberOfElements,
        BitSequence *output, BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to initialize the Tuple hash function TupleHash128 instance used in sequential hashing mode.
  * @param  TupleHashInstance     Pointer to the hash instance to be initialized.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash128_Initialize(TupleHash_Instance *TupleHashInstance, BitLength outputBitLen,
        const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be absorbed.
  * @param  TupleHashInstance     Pointer to the hash instance initialized by TupleHash128_Initialize().
  * @param  tuple            Pointer to an array of tuple elements (X).
  * @param  numberOfElements The number of tuple elements provided in the input data.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash128_Update(TupleHash_Instance *TupleHashInstance, const TupleElement *tuple, size_t numberOfElements);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling TupleHash128_Initialize().
  * @param  TupleHashInstance     Pointer to the hash instance initialized by TupleHash128_Initialize().
  * If @a outputBitLen was not 0 in the call to TupleHash128_Initialize(), the number of
  *     output bits is equal to @a outputBitLen.
  * If @a outputBitLen was 0 in the call to TupleHash128_Initialize(), the output bits
  *     must be extracted using the TupleHash128_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash128_Final(TupleHash_Instance *TupleHashInstance, BitSequence * output);

 /**
  * Function to squeeze output data.
  * @param  TupleHashInstance    Pointer to the hash instance initialized by TupleHash128_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    TupleHash128_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash128_Squeeze(TupleHash_Instance *TupleHashInstance, BitSequence *output, BitLength outputBitLen);

/* ------------------------------------------------------------------------- */

/** Tuple hash function TupleHash256, as defined in NIST's Special Publication 800-185,
  * published December 2016.
  * @param  tuple            Pointer to an array of tuple elements (X).
  * @param  numberOfElements The number of tuple elements provided in the input data.
  * @param  output           Pointer to the output buffer.
  * @param  outputBitLen     The desired number of output bits (L).
  * @param  customization    Pointer to the customization string (S).
  * @param  customBitLen     The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash256( const TupleElement *tuple, size_t numberOfElements,
        BitSequence *output, BitLength outputBitLen, const BitSequence *customization, BitLength customBitLen);

/**
  * Function to initialize the Tuple hash function TupleHash256 instance used in sequential hashing mode.
  * @param  TupleHashInstance     Pointer to the hash instance to be initialized.
  * @param  outputBitLen    The desired number of output bits (L).
  *                         or 0 for an arbitrarily-long output (XOF).
  * @param  customization   Pointer to the customization string (S).
  * @param  customBitLen    The length of the customization string in bits.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash256_Initialize(TupleHash_Instance *TupleHashInstance, BitLength outputBitLen,
        const BitSequence *customization, BitLength customBitLen);

/**
  * Function to give input data to be absorbed.
  * @param  TupleHashInstance     Pointer to the hash instance initialized by TupleHash256_Initialize().
  * @param  tuple            Pointer to an array of tuple elements (X).
  * @param  numberOfElements The number of tuple elements provided in the input data.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash256_Update(TupleHash_Instance *TupleHashInstance, const TupleElement *tuple, size_t numberOfElements);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling TupleHash256_Initialize().
  * @param  TupleHashInstance     Pointer to the hash instance initialized by TupleHash256_Initialize().
  * If @a outputBitLen was not 0 in the call to TupleHash256_Initialize(), the number of
  *     output bits is equal to @a outputBitLen.
  * If @a outputBitLen was 0 in the call to TupleHash256_Initialize(), the output bits
  *     must be extracted using the TupleHash256_Squeeze() function.
  * @param  output          Pointer to the buffer where to store the output data.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash256_Final(TupleHash_Instance *TupleHashInstance, BitSequence * output);

 /**
  * Function to squeeze output data.
  * @param  TupleHashInstance    Pointer to the hash instance initialized by TupleHash256_Initialize().
  * @param  output          Pointer to the buffer where to store the output data.
  * @param  outputBitLen    The number of output bits desired.
  *                         Only the last squeeze call can output a partial byte,
  *                         other calls must have a length multiple of 8.
  * @pre    TupleHash256_Final() must have been already called.
  * @return 0 if successful, 1 otherwise.
  */
int TupleHash256_Squeeze(TupleHash_Instance *TupleHashInstance, BitSequence *output, BitLength outputBitLen);

#else
#error This requires an implementation of Keccak-p[1600]
#endif

#endif
