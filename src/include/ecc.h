#ifndef  ECC_H
#define  ECC_H

    #include <stdint.h>

    //Mask difines consider 32 bit data
    #define MASK_D1 0b10000000000000000000000000000000
    #define MASK_D(n) (MASK_D1 >> (n-1))
    #define GET_D(n, data) ((data & MASK_D(n)) >> (32-n))

    typedef enum {
        NO_ERROR,
        SE,
        DE,
    } ecc_error_t;

    uint8_t ham_encode(uint32_t * data_in, uint8_t nb_databits, uint8_t nb_redbits);
    ecc_error_t ham_decode(uint32_t * data, uint8_t ecc, uint8_t nb_databits, uint8_t nb_redbits);
    uint8_t parity(uint32_t * data, uint8_t ecc, uint8_t nb_databits, uint8_t nb_redbits);

#endif  /*ECC_H*/
