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

#include "mmr.h"

static const unsigned DMNI_READ  = 0;
static const unsigned DMNI_WRITE = 1;

void dmni_read(void *payload_address, size_t payload_size)
{
	MMR_DMNI_SIZE = (unsigned int)payload_size;
	MMR_DMNI_OP = DMNI_WRITE;
	MMR_DMNI_ADDRESS = (unsigned int)payload_address;
	MMR_DMNI_START = 1;
	while(MMR_DMNI_RECEIVE_ACTIVE);
}

void dmni_send(packet_t *packet, void *payload, size_t size, bool should_free)
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

	MMR_DMNI_SIZE_2 = size;
	MMR_DMNI_ADDRESS_2 = (unsigned)outbound;

	MMR_DMNI_OP = DMNI_READ;

	pkt_set_dmni_info(packet, size);

	MMR_DMNI_START = 1;
}

void dmni_send_raw(unsigned *packet, size_t size)
{
	/* Wait for DMNI to be released */
	puts("ATENDE FILHO DA ME");
	while(MMR_DMNI_SEND_ACTIVE);
	puts("Vai programar");

	/* Program DMNI */
	MMR_DMNI_SIZE = size;
	MMR_DMNI_ADDRESS = (unsigned)packet;

	MMR_DMNI_SIZE_2 = 0;
	MMR_DMNI_ADDRESS = 0;

	MMR_DMNI_OP = DMNI_READ;

	MMR_DMNI_START = 1;

	while(MMR_DMNI_SEND_ACTIVE);
	puts("ALO QUENHE");
}
