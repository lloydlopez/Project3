/*
* transport.c
*
* COS461: Assignment 3 (STCP)
*
* This file implements the STCP layer that sits between the
* mysocket and network layers. You are required to fill in the STCP
* functionality in this file.
*
*/


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <iostream>
#include <unistd.h>
using namespace std;

#define WINDOW_SIZE 3072
#define MAX_SEQ_NUM 255
#define HEADER_SIZE 20

enum
{
	CSTATE_LISTEN,
	CSTATE_SYN_SENT,
	CSTATE_SYN_RECEIVED,
	CSTATE_ESTABLISHED,
	CSTATE_FIN_WAIT_1,
	CSTATE_FIN_WAIT_2,
	CSTATE_CLOSE_WAIT,
	CSTATE_CLOSING,
	CSTATE_LAST_ACK,
	CSTATE_TIME_WAIT,
	CSTATE_CLOSED
};

/* this structure is global to a mysocket descriptor */
typedef struct
{
	bool_t done;    /* TRUE once connection is closed */

	int connection_state;   /* state of the connection (established, etc.) */
	tcp_seq initial_sequence_num;

	tcp_seq sender_next_seq;
	tcp_seq receiver_next_seq;
	tcp_seq sender_unack_seq;

	uint16_t sender_window_size;
	uint16_t receiver_window_size;

	/* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
void close_connection_recv(mysocket_t sd, context_t *ctx, STCPHeader *fin_packet);
void close_connection_send(mysocket_t sd, context_t *ctx, STCPHeader *fin_packet);
void clear_header(tcphdr *header);

void handshake_err_handling(mysocket_t sd)
{
	errno = ECONNREFUSED;
	stcp_unblock_application(sd);
}

/* initialise the transport layer, and start the main loop, handling
* any data from the peer or the application.  this function should not
* return until the connection is closed.
*/
void transport_init(mysocket_t sd, bool_t is_active)
{
	cout << "INITIALIZE----" << endl;
	context_t *ctx;

	ctx = (context_t *)calloc(1, sizeof(context_t));
	assert(ctx);

	generate_initial_seq_num(ctx);

	ctx->sender_next_seq = ctx->initial_sequence_num;
	ctx->sender_unack_seq = ctx->initial_sequence_num;
	ctx->sender_window_size = WINDOW_SIZE;

	/* XXX: you should send a SYN packet here if is_active, or wait for one
	* to arrive if !is_active.  after the handshake completes, unblock the
	* application with stcp_unblock_application(sd).  you may also use
	* this to communicate an error condition back to the application, e.g.
	* if connection fails; to do so, just set errno appropriately (e.g. to
	* ECONNREFUSED, etc.) before calling the function.
	*/

	STCPHeader *header_packet; /* See STCPHeader in transport.h */
	header_packet = (STCPHeader *)calloc(1, HEADER_SIZE);
	assert(header_packet);

	if (is_active)
	{
		header_packet->th_seq = htonl(ctx->sender_next_seq);
		header_packet->th_flags = TH_SYN;
		header_packet->th_win = htons(ctx->sender_window_size);

		if (stcp_network_send(sd, header_packet, sizeof(STCPHeader), NULL) == -1)
		{
			handshake_err_handling(sd);
			return;
		}

		ctx->connection_state = CSTATE_SYN_SENT;

		if ((size_t)stcp_network_recv(sd, header_packet, sizeof(STCPHeader)) < sizeof(STCPHeader)) {
			handshake_err_handling(sd);
			return;
		}

		/* Need to check that SYN and ACK are both set */
		if (header_packet->th_flags != (TH_SYN | TH_ACK))
		{
			handshake_err_handling(sd);
			return;
		}

		header_packet->th_flags = TH_ACK;
		ctx->receiver_next_seq = ntohl(header_packet->th_seq) + 1;
		ctx->sender_next_seq = ntohl(header_packet->th_ack);
		ctx->receiver_window_size = ntohs(header_packet->th_win);
		ctx->sender_window_size = MIN(ntohs(header_packet->th_win), ctx->receiver_window_size);
		
		header_packet->th_seq = htonl(ctx->sender_next_seq);
		header_packet->th_ack = htonl(ctx->receiver_next_seq);
		header_packet->th_win = htons(MIN(ctx->receiver_window_size, ctx->sender_window_size));

		if (stcp_network_send(sd, header_packet, sizeof(STCPHeader), NULL) == -1)
		{
			handshake_err_handling(sd);
			return;
		}
	}
	else /* Passive end of the connection */
	{
		ctx->connection_state = CSTATE_LISTEN;

		if ((size_t)stcp_network_recv(sd, header_packet, sizeof(STCPHeader)) < sizeof(STCPHeader))
		{
			handshake_err_handling(sd);
			return;
		}

		ctx->connection_state = CSTATE_SYN_RECEIVED;

		ctx->receiver_next_seq = ntohl(header_packet->th_seq) + 1;
		ctx->sender_window_size = MIN(ntohs(header_packet->th_win), WINDOW_SIZE);
		ctx->receiver_window_size = WINDOW_SIZE;

		/* Next step is to check that SYN flag is set in received header (header_packet) */
		/* If so, set SYN and ACK flags and send message back to client */
		if (header_packet->th_flags == TH_SYN) {
			header_packet->th_win = htons(MIN(ctx->receiver_window_size, ctx->sender_window_size));
			header_packet->th_flags = TH_SYN + TH_ACK;
			header_packet->th_seq = htonl(ctx->sender_next_seq);
			header_packet->th_ack = htonl(ctx->receiver_next_seq);
			if (stcp_network_send(sd, header_packet, sizeof(STCPHeader), NULL) == -1)
			{
				handshake_err_handling(sd);
				return;
			}

			if ((size_t)stcp_network_recv(sd, header_packet, sizeof(STCPHeader)) < sizeof(STCPHeader))
			{
				handshake_err_handling(sd);
				return;
			}
		}
		else {
			printf("byte order issue");  //Remove before submitting
			handshake_err_handling(sd);
			return;
		}
	}

	ctx->connection_state = CSTATE_ESTABLISHED;
	
	stcp_unblock_application(sd);

	control_loop(sd, ctx);

	cout << "FINISHED CONTROL LOOP-----" << endl;

	/* do any cleanup here */
	free(ctx);
	free(header_packet);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
	assert(ctx);

#ifdef FIXED_INITNUM
	/* please don't change this! */
	ctx->initial_sequence_num = 1;
#else
	srand(*(unsigned int *)&ctx);
	ctx->initial_sequence_num = rand() % (MAX_SEQ_NUM+1);
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
* following to happen:
*   - incoming data from the peer
*   - new data from the application (via mywrite())
*   - the socket to be closed (via myclose())
*   - a timeout
*/
static void control_loop(mysocket_t sd, context_t *ctx)
{
	cout << "CONTROL LOOP FIRST TIME-----" << endl;
	assert(ctx);
	assert(!ctx->done);
	

	STCPHeader *header, *header_packet;	
	uint8_t *window = (uint8_t*)calloc(1, ctx->sender_window_size);
	uint8_t *window_ptr = (uint8_t*)calloc(1, ctx->sender_window_size);
	window_ptr = window;
	size_t sent;

	while (!ctx->done)
	{
		header = (STCPHeader *)calloc(1, HEADER_SIZE);
		
		cout << "IN WHILE LOOP----" << endl;
		unsigned int event;
		
		/* see stcp_api.h or stcp_api.c for details of this function */
		/* XXX: you will need to change some of these arguments! */
		event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
		
		cout << "EVENT----:" << event << endl;

		/* check whether it was the network, app, or a close request */
		if (event & APP_DATA)
		{
			cout << "APP DATA EVENT----" << endl;

			/* Make sure data is sent only if space is available */
			if (ctx->sender_next_seq < ctx->sender_unack_seq + ctx->receiver_window_size)
			{
				char packet[STCP_MSS] = { 0 };
					
				size_t packet_size = stcp_app_recv(sd, packet, STCP_MSS);
				
				ctx->sender_next_seq += packet_size;
				cout << "next1:" << ctx->sender_next_seq << endl;
				header->th_seq = htonl(ctx->sender_next_seq);
				header->th_ack = htonl(ctx->receiver_next_seq + 1);
				
				memcpy(window_ptr, header, HEADER_SIZE);
				window_ptr += HEADER_SIZE;
				memcpy(window_ptr, packet, packet_size);
				window_ptr += packet_size;
				ctx->sender_window_size -= (window_ptr - window);
				header->th_win = htons(ctx->sender_window_size);

				// Currently sending a new header plus the entire packet
				cout << "SENDING APP DATA OVER NETWORK" << endl;
				cout << "WINDOW PTR----" << window_ptr << endl;
				cout << "WINDOW----" << window << endl;
				sent = stcp_network_send(sd, window, window_ptr - window, NULL);
				ctx->sender_window_size += sent;
				window_ptr -= sent;
				

				clear_header(header);
			}
		}

		else if (event & NETWORK_DATA)
		{
			cout << "NETWORK DATA YEAH" << endl;
			uint8_t *header_data_packet = (uint8_t *)calloc(1, STCP_MSS);
			uint8_t *data = (uint8_t*)(window_ptr + sizeof(STCPHeader));
			uint16_t packet_length = stcp_network_recv(sd, header_data_packet, STCP_MSS);
			
			memcpy(window_ptr, header_data_packet, packet_length);
			window_ptr += packet_length;
			header_packet = (STCPHeader*)(window_ptr - packet_length);
			header_packet->th_off = 5;
			
			ctx->receiver_next_seq = ntohl(header_packet->th_seq) + 1;
			ctx->sender_next_seq = ctx->sender_next_seq + (packet_length-HEADER_SIZE);
			ctx->sender_unack_seq = ntohl(header_packet->th_seq) + 1;
			
			ctx->sender_window_size -= packet_length;
			ctx->receiver_window_size = ntohs(header_packet->th_win) + packet_length;
			ctx->sender_window_size = MIN(ctx->sender_window_size, ctx->receiver_window_size);
			
			

			if(sizeof(header_data_packet) > 20)
				cout << data << endl;
			

			if(header_packet->th_flags == TH_ACK){
				
				cout << "ACK RECEIVED" << endl;
				
				if(ctx->connection_state == CSTATE_FIN_WAIT_1)
				{
					cout << "switching to FIN_WAIT_2" << endl;
					ctx->connection_state = CSTATE_FIN_WAIT_2;					
				}
					
				else if(ctx->connection_state == CSTATE_LAST_ACK)
				{
					cout << "switching to LAST_ACK" << endl;
					ctx->connection_state = CSTATE_CLOSED;
					ctx->done = true;
				}
				else if(ctx->connection_state != CSTATE_ESTABLISHED){
					perror("NETWORK_DATA: ACK received in invalid state\n");
				}
					
			}
			else
			{
				cout << "ELSE EVENT-----" << endl;

				//send data to app
				cout << "data:" << data << endl;
				stcp_app_send(sd, data, packet_length - HEADER_SIZE);
				window_ptr -= (packet_length - HEADER_SIZE);
				ctx->sender_window_size += (packet_length - HEADER_SIZE);
				
			
				if(header_packet->th_flags == TH_FIN){				

					cout << "FIN RECEIVED" << endl;
					if (ctx->connection_state == CSTATE_ESTABLISHED)
						ctx->connection_state = CSTATE_CLOSE_WAIT;

					else if (ctx->connection_state == CSTATE_FIN_WAIT_1)
						ctx->connection_state = CSTATE_CLOSING;

					else if (ctx->connection_state == CSTATE_FIN_WAIT_2)
					{
						ctx->connection_state = CSTATE_CLOSED;
						ctx->done = true;
					}
					else
					{
						perror("NETWORK_DATA: FIN received in invalid state\n");
					}
					
					
					header_packet->th_seq = htonl(ctx->sender_next_seq);
					header_packet->th_ack = htonl(ctx->receiver_next_seq);
					header_packet->th_flags = TH_ACK;
					header_packet->th_win = ctx->sender_window_size;

					sent = stcp_network_send(sd, header_packet, HEADER_SIZE, NULL);
					window_ptr -= sent;
					ctx->sender_window_size += sent;
					stcp_fin_received(sd);

				}
				else 
				{  // send out ack
					cout << "sending ack" << endl;
					header_packet->th_seq = htonl(ctx->sender_next_seq);
					header_packet->th_ack = htonl(ctx->receiver_next_seq);
					header_packet->th_flags = TH_ACK;
					header_packet->th_win = ctx->sender_window_size;

					sent = stcp_network_send(sd, header_packet, HEADER_SIZE, NULL);
					ctx->sender_window_size += sent;
					stcp_fin_received(sd);
				}	
			}
		}

		else if (event & APP_CLOSE_REQUESTED)
		{
			cout << "CLOSE REQUEST YEAH" << endl;
			cout << ctx->connection_state << "bananas" << endl;
			if (ctx->connection_state == CSTATE_ESTABLISHED)
				ctx->connection_state = CSTATE_FIN_WAIT_1;

			else if (ctx->connection_state == CSTATE_CLOSE_WAIT)
				ctx->connection_state = CSTATE_LAST_ACK;

			else
			{
				perror("APP_CLOSE_REQUESTED: invalid state\n");
			}

			header_packet->th_seq = htonl(ctx->sender_next_seq);
			header_packet->th_ack = htonl(ctx->receiver_next_seq);
			header_packet->th_flags = TH_FIN;
			header_packet->th_win = htons(ctx->receiver_window_size);
			cout << "PRE-FINAL SEND" << endl;

			stcp_network_send(sd, header_packet, HEADER_SIZE, NULL);
			cout << "POST-FINAL SEND" << endl;
		}

		free(header);
	}
	
	cout<<"EXITING CONTROL LOOP\n";
}

void clear_header(tcphdr *header)
{
	header->th_flags = 0;
	header->th_ack = 0;
	header->th_seq = 0;
	header->th_win = 0;
}

/**********************************************************************/
/* our_dprintf
*
* Send a formatted message to stdout.
*
* format               A printf-style format string.
*
* This function is equivalent to a printf, but may be
* changed to log errors to a file if desired.
*
* Calls to this function are generated by the dprintf amd
* dperror macros in transport.h
*/
void our_dprintf(const char *format, ...)
{
	va_list argptr;
	char buffer[1024];

	assert(format);
	va_start(argptr, format);
	vsnprintf(buffer, sizeof(buffer), format, argptr);
	va_end(argptr);
	fputs(buffer, stdout);
	fflush(stdout);
}
