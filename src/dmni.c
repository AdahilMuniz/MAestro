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

	/*
	static int ecc_cnt = 0;
	if (ecc_cnt++ % 4 == 0)
	{
		payload[flit_cnt  ] = 3;
		payload[flit_cnt+1] = 2;
		payload[flit_cnt+2] = 1;
		payload[flit_cnt+3] = 0;
	} else {
		payload[flit_cnt  ] = 0;
		payload[flit_cnt+1] = 1;
		payload[flit_cnt+2] = 2;
		payload[flit_cnt+3] = 3;
	}

	printf("ECC enviado: %x %x %x %x\n", payload[flit_cnt], payload[flit_cnt+1], payload[flit_cnt+2], payload[flit_cnt+3]);
	*/

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

	for (int j = 1; j < payload_size; j=j+2){
		if (j !=  payload_size-1){
        	ecc[6+(j/2)] = (uint8_t) ham_encode((uint32_t *)payload [j], 64, 7);
        } else { //Last only one flit
        	ecc[6+(j/2)] = (uint8_t) ham_encode((uint32_t *)payload [j], 32, 6);
        }
	}

	//payload[flit_cnt  ] = (int) {ecc[ 0], ecc[ 1], ecc[ 2], ecc[ 3]};
	//payload[flit_cnt+1] = (int) {ecc[ 4], ecc[ 5], ecc[ 6], ecc[ 7]};
	//payload[flit_cnt+2] = (int) {ecc[ 8], ecc[ 9], ecc[10], ecc[11]};
	//payload[flit_cnt+3] = (int) {ecc[12], ecc[13], ecc[14], ecc[15]};

	payload[flit_cnt  ] = (int) (ecc[ 0] | (ecc[ 1] << 8) | (ecc[ 2] << 16) | (ecc[ 3] << 24) );
	payload[flit_cnt+1] = (int) (ecc[ 4] | (ecc[ 5] << 8) | (ecc[ 6] << 16) | (ecc[ 7] << 24) );
	payload[flit_cnt+2] = (int) (ecc[ 8] | (ecc[ 9] << 8) | (ecc[10] << 16) | (ecc[11] << 24) );
	payload[flit_cnt+3] = (int) (ecc[12] | (ecc[13] << 8) | (ecc[14] << 16) | (ecc[15] << 24) );

	/*
	for (int i = 6; i < ECC_SIZE; i++) { // Iterate over each flit of ecc
        //for (int j = 0; j < ((PKT_SIZE-2) + payload_size)/ECC_SIZE; j=j+2){ // Iterate over each block of flits
		for (int j = 1; j < payload_size; j=j+2){ // Iterate over each block of flits
			//if ((j/2) + i*ECC_SIZE < (PKT_SIZE-3)) { // On header [0-9]
			//	ecc[(j/2) + i*ECC_SIZE] = (char) ham_encode(packet[2 + j + i*(((PKT_SIZE-2) + payload_size)/ECC_SIZE)], 64, 7);
			//}
			//else if ((j/2) + i*ECC_SIZE == (PKT_SIZE-3)) { // On header [10] + Payload [0]
			//	//double_data_aux[0] = packet[2 + j + i*(((PKT_SIZE-2) + payload_size)/ECC_SIZE)];
			//	double_data_aux[0] = packet->with_ecc;
			//	double_data_aux[1] = payload [j + i*(((PKT_SIZE-2) + payload_size)/ECC_SIZE)];
			//}
			//else { // On Payload [1 - Inf]
				if (j !=  (((PKT_SIZE-2) + payload_size)/ECC_SIZE)-1){
                	ecc[(j/2) + i*ECC_SIZE] = (char) ham_encode(payload [j + i*(((PKT_SIZE-2) + payload_size)/ECC_SIZE)], 64, 7);
            	} else { //Last only one flit
                	ecc[(j/2) + i*ECC_SIZE] = (char) ham_encode(payload [j + i*(((PKT_SIZE-2) + payload_size)/ECC_SIZE)], 32, 6);
            	}
			//}
        }
    }
	*/
	
}
