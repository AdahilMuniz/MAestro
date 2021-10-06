/**
 * MA-Memphis
 * @file Memphis.cpp
 * 
 * @author Unknown
 * GAPH - Hardware Design Support Group (https://corfu.pucrs.br/)
 * PUCRS - Pontifical Catholic University of Rio Grande do Sul (http://pucrs.br/)
 * 
 * @date September 2013
 * 
 * @brief Control of router position
 */

#include "Memphis.hpp"

Memphis::Memphis(sc_module_name name_, std::string path) :
	sc_module(name_)
{
	for(int j = 0; j < N_PE; j++){
		regaddress r_addr = RouterAddress(j);
		int x_addr = ((int) r_addr) >> 8;
		int y_addr = ((int) r_addr) & 0xFF;

		char pe_name[20];
		sprintf(pe_name, "PE%dx%d", x_addr, y_addr);
		printf("Creating PE %s\n", pe_name);

		pe[j] = new PE(pe_name, r_addr, path);
		pe[j]->clock(clock);
		pe[j]->reset(reset);

		for(int i = 0; i < NPORT - 1; i++){
			pe[j]->tx[i](tx[j][i]);
			pe[j]->data_out[i](data_out[j][i]);
			pe[j]->credit_i[i](credit_i[j][i]);
			pe[j]->data_in[i](data_in[j][i]);
			pe[j]->rx[i](rx[j][i]);
			pe[j]->credit_o[i](credit_o[j][i]);

			pe[j]->br_req_in[i](br_req_in[j][i]);
			pe[j]->br_ack_in[i](br_ack_in[j][i]);
			pe[j]->br_payload_in[i](br_payload_in[j][i]);
			pe[j]->br_address_in[i](br_address_in[j][i]);
			pe[j]->br_producer_in[i](br_producer_in[j][i]);
			pe[j]->br_id_svc_in[i](br_id_svc_in[j][i]);
			pe[j]->br_ksvc_in[i](br_ksvc_in[j][i]);

			pe[j]->br_req_out[i](br_req_out[j][i]);
			pe[j]->br_ack_out[i](br_ack_out[j][i]);
			pe[j]->br_payload_out[i](br_payload_out[j][i]);
			pe[j]->br_address_out[i](br_address_out[j][i]);
			pe[j]->br_producer_out[i](br_producer_out[j][i]);
			pe[j]->br_id_svc_out[i](br_id_svc_out[j][i]);
			pe[j]->br_ksvc_out[i](br_ksvc_out[j][i]);
		}
	}

	SC_METHOD(pes_interconnection);
	sensitive << memphis_app_injector_tx;
	sensitive << memphis_app_injector_credit_i;
	sensitive << memphis_app_injector_data_out;
	sensitive << memphis_app_injector_rx;
	sensitive << memphis_app_injector_credit_o;
	sensitive << memphis_app_injector_data_in;
	sensitive << memphis_ma_injector_tx;
	sensitive << memphis_ma_injector_credit_i;
	sensitive << memphis_ma_injector_data_out;
	sensitive << memphis_ma_injector_rx;
	sensitive << memphis_ma_injector_credit_o;
	sensitive << memphis_ma_injector_data_in;
	for(int j = 0; j < N_PE; j++){
		for(int i = 0; i < NPORT - 1; i++){
			sensitive << tx[j][i];
			sensitive << data_out[j][i];
			sensitive << credit_i[j][i];
			sensitive << data_in[j][i];
			sensitive << rx[j][i];
			sensitive << credit_o[j][i];
		}
	}

	SC_METHOD(br_interconnection);
	for(int j = 0; j < N_PE; j++){
		for(int i = 0; i < NPORT - 1; i++){
			sensitive << br_req_in[j][i];
			sensitive << br_ack_in[j][i];
			sensitive << br_payload_in[j][i];
			sensitive << br_address_in[j][i];
			sensitive << br_producer_in[j][i];
			sensitive << br_id_svc_in[j][i];
			sensitive << br_ksvc_in[j][i];

			sensitive << br_req_out[j][i];
			sensitive << br_ack_out[j][i];
			sensitive << br_payload_out[j][i];
			sensitive << br_address_out[j][i];
			sensitive << br_producer_out[j][i];
			sensitive << br_id_svc_out[j][i];
			sensitive << br_ksvc_out[j][i];
		}
	}
}

int Memphis::RouterPosition(int router)
{
	int pos;
	
	int column = router%N_PE_X;
	
	if(router>=(N_PE-N_PE_X)){ //TOP
		if(column==(N_PE_X-1)){ //RIGHT
			pos = TR;
		}
		else{
			if(column==0){//LEFT
				pos = TL;
			}
			else{//CENTER_X
				pos = TC;
			}
		}
	}
	else{
		if(router<N_PE_X){ //BOTTOM
			if(column==(N_PE_X-1)){ //RIGHT
				pos = BR;
			}
			else{
				if(column==0){//LEFT
					pos = BL;
				}
				else{//CENTER_X
					pos = BC;
				}
			}
		}
		else{//CENTER_Y
			if(column==(N_PE_X-1)){ //RIGHT
				pos = CRX;
			}
			else{
				if(column==0){//LEFT
					pos = CL;
				}
				else{//CENTER_X
					pos = CC;
				}
			}
		}
	}
			
	return pos;
}

regaddress Memphis::RouterAddress(int router)
{
	regaddress r_address;
	
	sc_uint<8> pos_y = (unsigned int) router/N_PE_X;
	sc_uint<8> pos_x = router%N_PE_X;

	r_address[15] = pos_x[7];
	r_address[14] = pos_x[6];
	r_address[13] = pos_x[5];
	r_address[12] = pos_x[4];
	r_address[11] = pos_x[3];
	r_address[10] = pos_x[2];
	r_address[ 9] = pos_x[1];
	r_address[ 8] = pos_x[0];
	r_address[7] = pos_y[7];
	r_address[6] = pos_y[6];
	r_address[5] = pos_y[5];
	r_address[4] = pos_y[4];
	r_address[3] = pos_y[3];
	r_address[2] = pos_y[2];
	r_address[1] = pos_y[1];
	r_address[0] = pos_y[0];
		
	return r_address;	
}


void Memphis::pes_interconnection()
{ 	 	
 	for(int i = 0; i < N_PE; i++){
		//EAST GROUNDING
 		if(RouterPosition(i) == BR || RouterPosition(i) == CRX || RouterPosition(i) == TR){
 			if (io_port[i] != EAST){//If the port in not connected to an IO then:
				credit_i[i][EAST].write(0);
				data_in [i][EAST].write(0);
				rx      [i][EAST].write(0);
 			}
		} else {//EAST CONNECTION
 			credit_i[i][EAST].write(credit_o[i+1][WEST].read());
 			data_in [i][EAST].write(data_out[i+1][WEST].read());
 			rx      [i][EAST].write(tx      [i+1][WEST].read());
 		}
 		
 		//WEST GROUNDING
 		if(RouterPosition(i) == BL || RouterPosition(i) == CL || RouterPosition(i) == TL){
 			if (io_port[i] != WEST){
				credit_i[i][WEST].write(0);
				data_in [i][WEST].write(0);
				rx      [i][WEST].write(0);
 			}
 		} else {//WEST CONNECTION
			credit_i[i][WEST].write(credit_o[i-1][EAST].read());
 			data_in [i][WEST].write(data_out[i-1][EAST].read());
 			rx      [i][WEST].write(tx      [i-1][EAST].read());
 		}
 		
 		//NORTH GROUNDING
 		if(RouterPosition(i) == TL || RouterPosition(i) == TC || RouterPosition(i) == TR){
 			if (io_port[i] != NORTH){
				credit_i[i][NORTH].write(1);
				data_in [i][NORTH].write(0);
				rx      [i][NORTH].write(0);
 			}
 		} else {//NORTH CONNECTION
			credit_i[i][NORTH].write(credit_o[i+N_PE_X][SOUTH].read());
 			data_in [i][NORTH].write(data_out[i+N_PE_X][SOUTH].read());
 			rx      [i][NORTH].write(tx      [i+N_PE_X][SOUTH].read());
 		}
 		
 		//SOUTH GROUNDING
 		if(RouterPosition(i) == BL || RouterPosition(i) == BC || RouterPosition(i) == BR){
 			if (io_port[i] != SOUTH){
				credit_i[i][SOUTH].write(0);
				data_in [i][SOUTH].write(0);
				rx      [i][SOUTH].write(0);
 			}
 		} else{//SOUTH CONNECTION
			credit_i[i][SOUTH].write(credit_o[i-N_PE_X][NORTH].read());
 			data_in [i][SOUTH].write(data_out[i-N_PE_X][NORTH].read());
 			rx      [i][SOUTH].write(tx      [i-N_PE_X][NORTH].read());
 		}

 		//--IO Wiring (Memphis <-> AppInjector) ----------------------
 		if (i == APP_INJECTOR && io_port[i] != NPORT) {
 			int p = io_port[i];
			memphis_app_injector_tx.write(tx[APP_INJECTOR][p].read());
			memphis_app_injector_data_out.write(data_out[APP_INJECTOR][p].read());
			credit_i[APP_INJECTOR][p].write(memphis_app_injector_credit_i.read());

			rx[APP_INJECTOR][p].write(memphis_app_injector_rx.read());
			memphis_app_injector_credit_o.write(credit_o[APP_INJECTOR][p].read());
			data_in[APP_INJECTOR][p].write(memphis_app_injector_data_in.read());
 		}
 		//--IO Wiring (Memphis <-> MAInjector) ----------------------
		if (i == MAINJECTOR && io_port[i] != NPORT) {
 			int p = io_port[i];
			memphis_ma_injector_tx.write(tx[MAINJECTOR][p].read());
			memphis_ma_injector_data_out.write(data_out[MAINJECTOR][p].read());
			credit_i[MAINJECTOR][p].write(memphis_ma_injector_credit_i.read());

			rx[MAINJECTOR][p].write(memphis_ma_injector_rx.read());
			memphis_ma_injector_credit_o.write(credit_o[MAINJECTOR][p].read());
			data_in[MAINJECTOR][p].write(memphis_ma_injector_data_in.read());
 		}
		//Insert the IO wiring for your component here if it connected to a port:
 	}
}

void Memphis::br_interconnection()
{
	for(int y = 0; y < N_PE_Y; y++){
		for(int x = 0; x < N_PE_X; x++){
			if(y != N_PE_Y - 1){
				br_req_in[y*N_PE_X + x][NORTH] = br_req_out[y*N_PE_X + x + N_PE_X][SOUTH];
				br_ack_in[y*N_PE_X + x][NORTH] = br_ack_out[y*N_PE_X + x + N_PE_X][SOUTH];
				br_address_in[y*N_PE_X + x][NORTH] = br_address_out[y*N_PE_X + x + N_PE_X][SOUTH];
				br_payload_in[y*N_PE_X + x][NORTH] = br_payload_out[y*N_PE_X + x + N_PE_X][SOUTH];
				br_producer_in[y*N_PE_X + x][NORTH] = br_producer_out[y*N_PE_X + x + N_PE_X][SOUTH];
				br_id_svc_in[y*N_PE_X + x][NORTH] = br_id_svc_out[y*N_PE_X + x + N_PE_X][SOUTH];
				br_ksvc_in[y*N_PE_X + x][NORTH] = br_ksvc_out[y*N_PE_X + x + N_PE_X][SOUTH];
			} else {
				/* Ground signals */
				br_req_in[y*N_PE_X + x][NORTH] = 0;
				br_ack_in[y*N_PE_X + x][NORTH] = 1;
				br_address_in[y*N_PE_X + x][NORTH] = 0;
				br_payload_in[y*N_PE_X + x][NORTH] = 0;
				br_producer_in[y*N_PE_X + x][NORTH] = 0;
				br_id_svc_in[y*N_PE_X + x][NORTH] = 0;
				br_ksvc_in[y*N_PE_X + x][NORTH] = 0;
			}

			if(y != 0){
				br_req_in[y*N_PE_X + x][SOUTH] = br_req_out[y*N_PE_X + x - N_PE_X][NORTH];
				br_ack_in[y*N_PE_X + x][SOUTH] = br_ack_out[y*N_PE_X + x - N_PE_X][NORTH];
				br_address_in[y*N_PE_X + x][SOUTH] = br_address_out[y*N_PE_X + x - N_PE_X][NORTH];
				br_payload_in[y*N_PE_X + x][SOUTH] = br_payload_out[y*N_PE_X + x - N_PE_X][NORTH];
				br_producer_in[y*N_PE_X + x][SOUTH] = br_producer_out[y*N_PE_X + x - N_PE_X][NORTH];
				br_id_svc_in[y*N_PE_X + x][SOUTH] = br_id_svc_out[y*N_PE_X + x - N_PE_X][NORTH];
				br_ksvc_in[y*N_PE_X + x][SOUTH] = br_ksvc_out[y*N_PE_X + x - N_PE_X][NORTH];
			} else {
				/* Ground signals */
				br_req_in[y*N_PE_X + x][SOUTH] = 0;
				br_ack_in[y*N_PE_X + x][SOUTH] = 1;
				br_address_in[y*N_PE_X + x][SOUTH] = 0;
				br_payload_in[y*N_PE_X + x][SOUTH] = 0;
				br_producer_in[y*N_PE_X + x][SOUTH] = 0;
				br_id_svc_in[y*N_PE_X + x][SOUTH] = 0;
				br_ksvc_in[y*N_PE_X + x][SOUTH] = 0;
			}

			if(x != N_PE_X - 1){
				br_req_in[y*N_PE_X + x][EAST] = br_req_out[y*N_PE_X + x + 1][WEST];
				br_ack_in[y*N_PE_X + x][EAST] = br_ack_out[y*N_PE_X + x + 1][WEST];
				br_address_in[y*N_PE_X + x][EAST] = br_address_out[y*N_PE_X + x + 1][WEST];
				br_payload_in[y*N_PE_X + x][EAST] = br_payload_out[y*N_PE_X + x + 1][WEST];
				br_producer_in[y*N_PE_X + x][EAST] = br_producer_out[y*N_PE_X + x + 1][WEST];
				br_id_svc_in[y*N_PE_X + x][EAST] = br_id_svc_out[y*N_PE_X + x + 1][WEST];
				br_ksvc_in[y*N_PE_X + x][EAST] = br_ksvc_out[y*N_PE_X + x + 1][WEST];
			} else {
				/* Ground signals */
				br_req_in[y*N_PE_X + x][EAST] = 0;
				br_ack_in[y*N_PE_X + x][EAST] = 1;
				br_address_in[y*N_PE_X + x][EAST] = 0;
				br_payload_in[y*N_PE_X + x][EAST] = 0;
				br_producer_in[y*N_PE_X + x][EAST] = 0;
				br_id_svc_in[y*N_PE_X + x][EAST] = 0;
				br_ksvc_in[y*N_PE_X + x][EAST] = 0;
			}

			if(x != 0){
				br_req_in[y*N_PE_X + x][WEST] = br_req_out[y*N_PE_X + x - 1][EAST];
				br_ack_in[y*N_PE_X + x][WEST] = br_ack_out[y*N_PE_X + x - 1][EAST];
				br_address_in[y*N_PE_X + x][WEST] = br_address_out[y*N_PE_X + x - 1][EAST];
				br_payload_in[y*N_PE_X + x][WEST] = br_payload_out[y*N_PE_X + x - 1][EAST];
				br_producer_in[y*N_PE_X + x][WEST] = br_producer_out[y*N_PE_X + x - 1][EAST];
				br_id_svc_in[y*N_PE_X + x][WEST] = br_id_svc_out[y*N_PE_X + x - 1][EAST];
				br_ksvc_in[y*N_PE_X + x][WEST] = br_ksvc_out[y*N_PE_X + x - 1][EAST];
			} else {
				/* Ground signals */
				br_req_in[y*N_PE_X + x][WEST] = 0;
				br_ack_in[y*N_PE_X + x][WEST] = 1;
				br_address_in[y*N_PE_X + x][WEST] = 0;
				br_payload_in[y*N_PE_X + x][WEST] = 0;
				br_producer_in[y*N_PE_X + x][WEST] = 0;
				br_id_svc_in[y*N_PE_X + x][WEST] = 0;
				br_ksvc_in[y*N_PE_X + x][WEST] = 0;
			}
		}
	}
}
