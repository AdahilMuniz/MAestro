/**
 * MA-Memphis
 * @file dmni.c
 * 
 * @author Angelo Elias Dalzotto (angelo.dalzotto@edu.pucrs.br)
 * GAPH - Hardware Design Support Group (https://corfu.pucrs.br/)
 * PUCRS - Pontifical Catholic University of Rio Grande do Sul (http://pucrs.br/)
 * 
 * @date September 2020
 * 
 * @brief Defines the DMNI functions for payload handling.
 */

#include "dmni.h"

#include <stdlib.h>
#include <stdio.h>

#include "mmr.h"

static const unsigned DMNI_READ  = 0;
static const unsigned DMNI_WRITE = 1;

int dmni_read(void *payload_address, size_t payload_size)
{
    MMR_DMNI_SIZE = (unsigned int)payload_size;
    MMR_DMNI_OP = DMNI_WRITE;
    MMR_DMNI_ADDRESS = (unsigned int)payload_address;
    MMR_DMNI_START = 1;
    while(MMR_DMNI_RECEIVE_ACTIVE);
    return MMR_DMNI_READ_FLITS;
}

void dmni_send(packet_t *packet, void *payload, size_t size, bool should_free, bool with_ecc)
{
    static bool free_outbound = false;
    static void *outbound = NULL;

    /* Wait for DMNI to be released */
    while(MMR_DMNI_SEND_ACTIVE);

    if(free_outbound)
        free(outbound);

    outbound = payload;
    free_outbound = should_free;

    /* Program DMNI */
    MMR_DMNI_SIZE = PKT_SIZE;
    MMR_DMNI_ADDRESS = (unsigned)packet;

    MMR_DMNI_SIZE_2 = size + (with_ecc ? 4 : 0);
    MMR_DMNI_ADDRESS_2 = (unsigned)outbound;

    MMR_DMNI_OP = DMNI_READ;

    pkt_set_dmni_info(packet, size + (with_ecc ? 4 : 0));

    if (with_ecc)
        dmni_set_ecc(packet, payload, size);

    MMR_DMNI_START = 1;
}

void dmni_send_raw(unsigned *packet, size_t size)
{
    /* Wait for DMNI to be released */
    // puts("[DMNI] Waiting for DMNI to be released.");
    while(MMR_DMNI_SEND_ACTIVE);
    // puts("[DMNI] DMNI released, sending.");

    /* Program DMNI */
    MMR_DMNI_SIZE = size;
    MMR_DMNI_ADDRESS = (unsigned)packet;

    // printf("Addr = %x\n", (unsigned)packet);
    // for(int i = 0; i < size; i++){
    // 	printf("%d\n", packet[i]);
    // }

    MMR_DMNI_SIZE_2 = 0;
    MMR_DMNI_ADDRESS_2 = 0;

    MMR_DMNI_OP = DMNI_READ;

    MMR_DMNI_START = 1;

    while(MMR_DMNI_SEND_ACTIVE);
    // puts("[DMNI] Sent.");
}

void dmni_drop_payload()
{
    // printf("Dropping payload - Size = %u\n", payload_size);
    MMR_DMNI_OP = DMNI_WRITE;
    MMR_DMNI_ADDRESS = 0;
    MMR_DMNI_START = 1;
    while(MMR_DMNI_RECEIVE_ACTIVE);
    // printf("Payload dropped\n");
}

void dmni_set_ecc(packet_t *packet, int *payload, size_t flit_cnt)
{
    /* Computar ECC para packet + payload 				  */
    /* Como exemplo estou adicionando os dados 0, 1, 2, 3 */
    /* Os 4 flits adicionais já estão alocados em memória */
    /* A cada 4 mensagens com ecc eu gero um ecc inválido */
    /* Disparando um re-envio 						      */

    /* ATENÇÃO: ignorar packet[0] e packet[1] (TARGET e SIZE) */

    size_t payload_size = flit_cnt - (PKT_SIZE + ECC_SIZE);
    int double_data_aux [2];
    uint8_t ecc [ECC_SIZE*4];


    // @NOTE: This is not the best way to do this. The ideal would be to have a union with the payload and header, 
    // so we could iterate over them as if they were a single vector. To avoid to much modification on MAestro
    // source code, I decided to keep the ECC codification like this.

    double_data_aux[0] = packet->service;
    double_data_aux[1] = packet->producer_task;
    ecc[0] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);

    double_data_aux[0] = packet->consumer_task;
    double_data_aux[1] = packet->source_PE;
    ecc[1] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);

    double_data_aux[0] = packet->timestamp;
    double_data_aux[1] = packet->transaction;
    ecc[2] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);

    double_data_aux[0] = packet->mapper_task;
    double_data_aux[1] = packet->waiting_msg;
    ecc[3] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);

    double_data_aux[0] = packet->code_size;
    double_data_aux[1] = packet->bss_size;
    ecc[4] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);

    double_data_aux[0] = packet->program_counter;
    double_data_aux[1] = payload[0];
    ecc[5] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);

    for (int j = 1; j < flit_cnt; j=j+2){
        if (j !=  flit_cnt-1){
            // OBS.: As 'payload' points to a function heap address, we can't pass it directly 
            // to the ham_decode, since it can't access it, so it was need to do this "intermediation"
            // to avoid re-work.
            double_data_aux[0] = payload [j];
            double_data_aux[1] = payload [j+1];
            ecc[6+(j/2)] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 64, 7);
        } else { //Last only one flit
            double_data_aux[0] = payload [j];
            ecc[6+(j/2)] = (uint8_t) ham_encode((uint32_t *)double_data_aux, 32, 6);
        }
    }

    payload[flit_cnt  ] = (int) (ecc[ 0] | (ecc[ 1] << 8) | (ecc[ 2] << 16) | (ecc[ 3] << 24) );
    payload[flit_cnt+1] = (int) (ecc[ 4] | (ecc[ 5] << 8) | (ecc[ 6] << 16) | (ecc[ 7] << 24) );
    payload[flit_cnt+2] = (int) (ecc[ 8] | (ecc[ 9] << 8) | (ecc[10] << 16) | (ecc[11] << 24) );
    payload[flit_cnt+3] = (int) (ecc[12] | (ecc[13] << 8) | (ecc[14] << 16) | (ecc[15] << 24) );
    
}
