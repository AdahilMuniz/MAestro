#include "ecc.h"

//@NOTE: For simple hamming code, considering n == word bits number and r == refundancy bits number.
//2^r - 1 >= n, so, for n==64, r==7 and n==32, r==6. For extended hamming code, add one to r result.

//@NOTE (deprected): For code efficiency, we will create two function, one for (72, 64) and another one for (39, 32).
//However, it is always possible to implement a method to search for a r value given an n value. To make
//it easy, the methods will also add the parity bit at the end and will encode the ecc in 8 bits.


/**
 * \brief Calculate the extended humming code considering the data and redudancy length.
 *
 * This function takes the data, the respective lengths and return the calculated ECC. All the ECCs will be 
 * stored starting from MSB of a uint8_t variable. For example, fo 3 redudancy bits: 
 * Position:  7  6  5  4  3  2  1  0
 * Value   : e2 e1 e0  P  0  0  0  0 
 * 
 * \param data_in Data Input.
 * \param nb_databits Data length in bits.
 * \param nb_redbits Redundancy length in bits (only hamming, no parity).
 * \return The ECC as a uint8_t type, where the first redundancy bit is in the MSB.
 */

uint8_t ham_encode(uint32_t * data_in, uint8_t nb_databits, uint8_t nb_redbits){
    uint8_t ecc = 0;
    uint8_t partial_ecc = 0;
    uint8_t nb_totalbits = nb_databits + nb_redbits;
    uint8_t nb_found_redbits = 0;
    uint8_t flit = 0;
    uint8_t p = 0;

    // Calculating Hamming
    for (uint8_t j = 0; j < nb_redbits; j++){ // Iterate over the reundancy bits
        for (uint8_t i = 1; i < nb_totalbits; i++){ // Iterate over the entire data (redudancy + data)
            if ( (i & (0b00000001 << j)) &&  (i & (~(0b00000001 << j))) ) { // Check if the referent redundancy bit is set and if it's power of two == it is a parity position
                for (uint8_t k = 0; k < nb_redbits; k++) { // Iterate over the power of two, so we can covert the struct postion to data position 
                    if (i & (0b00000001 << k)){ // Check it already "passed" by a redundancy
                        nb_found_redbits = k +1; // Count the number of redundancy bits already "passed"
                    }
                }
                flit = (uint8_t) ((i-nb_found_redbits)/32);
                //printf("FLIT: %d\n", flit);
                partial_ecc ^= GET_D( ((i-nb_found_redbits)%32) , data_in[flit]);
            }
        }
        ecc |= partial_ecc << (8 - (nb_redbits-j));//keep it begining from the MSB
        partial_ecc = 0;
    }

    p = parity(data_in, ecc, nb_databits, nb_redbits);

    ecc |= p << (7-nb_redbits);//keep it begining from the MSB

    return ecc;
}


/**
 * \brief Check and (if possible) correct errors of a data input regarding the ECC.
 *
 * This function takes the data, the respective lengths, the ECC and return the type of the error found
 * sC sP  Error
 *  0  0  No Error
 *  0  1  Single Error (SE) (on redundancy area) -> No modification
 *  1  0  Double Error (DE)
 *  1  1  Single Error (SE) (on data area) -> Correct error on data_in
 * 
 * \param data Data.
 * \param ecc The previous calculated ECC as a uint8_t type, where the first redundancy bit is in the MSB.
 * \param nb_databits Data length in bits.
 * \param nb_redbits Redundancy length in bits (only hamming, no parity).
 * \return A ecc_error_t type indicating the error kind
 */

ecc_error_t ham_decode(uint32_t * data, uint8_t ecc, uint8_t nb_databits, uint8_t nb_redbits){
    uint8_t recalc_ecc;
    uint8_t synd;
    uint8_t mask = 0;
    uint8_t p;
    ecc_error_t err;

    //Auxiliary to correct error
    uint8_t nb_found_redbits = 0;
    uint8_t flit = 0;
    uint8_t position = 0;

    recalc_ecc = ham_encode(data, nb_databits, nb_redbits);
    printf("RECALC ECC: %x\n", recalc_ecc);

    //OBS.: The parity calculated for recalc_ecc is not correct since it takes into account the just calculated ECC
    //not the previous one, so we have to calculate the correct parity
    p = parity(data, ecc, nb_databits, nb_redbits);
    recalc_ecc &= (~(0b00000001 << (7-nb_redbits)));
    recalc_ecc |= p << (7-nb_redbits);

    //Calculate Syndrome
    synd = ecc ^ recalc_ecc;

    //Building hamming redundancy mask
    for (uint8_t i = 0; i < nb_redbits; i++){
        mask |= 0b00000001 << i;
    }
    mask = mask << (8-nb_redbits);

    //Check and correct
    if (!(synd & mask) && !(synd & ~mask)){
        err = NO_ERROR;
    } else if (!(synd & mask) && (synd & ~mask)){
        err = SE;
    } else if ((synd & mask) && !(synd & ~mask)){
        err = DE;
    } else {
        err = SE;

        synd = (synd & mask) >> (8-nb_redbits);

        for (uint8_t k = 0; k < nb_redbits; k++) { // Iterate over the power of two, so we can covert the struct postion to data position 
            if (synd & (0b00000001 << k)){ // Check it already "passed" by a redundancy
                nb_found_redbits = k +1; // Count the number of redundancy bits already "passed"
            }
        }

        flit = (uint8_t) ((synd-nb_found_redbits)/32);
        position = (uint8_t) 32 - ((synd-nb_found_redbits)%32); // Considering MSB

        data[flit] ^= 0x00000001 << position; //Flip the bit indicated by position
    }
    
    return err;
}


/**
 * \brief Calculate parity between all the data and ECC bits
 *
 * This function takes the data, the respective lengths, the ECC and return the parity
 * 
 * \param data Data.
 * \param ecc The previous calculated ECC as a uint8_t type, where the first redundancy bit is in the MSB.
 * \param nb_databits Data length in bits.
 * \param nb_redbits Redundancy length in bits (only hamming, no parity).
 * \return A uint8_t type representing the parity
 */
uint8_t parity(uint32_t * data, uint8_t ecc, uint8_t nb_databits, uint8_t nb_redbits){
    uint8_t flit = 0;
    uint8_t p = 0;

    // Calculating Parity
    for (uint8_t i = 0; i < nb_databits; i++) {
        flit = (uint8_t) (i/32);
        p ^= GET_D(((i%32)+1), data[flit]);
    }
    for (uint8_t i = 0; i < nb_redbits; i++) {
        p ^= ((ecc >> (7-i)) & 0b00000001);
    }
    return p;
}