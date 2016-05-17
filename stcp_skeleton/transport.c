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

#define WINDOW_SIZE 3072

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

	uint16_t sender_window_size;
	uint16_t receiver_window_size;

    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

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
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

	ctx->sender_next_seq = ctx->initial_sequence_num;
	ctx->receiver_window_size = WINDOW_SIZE;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

	STCPHeader *syn_packet; /* See STCPHeader in transport.h */
	syn_packet = (STCPHeader *)calloc(1, sizeof(STCPHeader));
	assert(syn_packet);

	if (is_active)
	{	
		syn_packet->th_seq = htons(ctx->sender_next_seq);
		syn_packet->th_flags = TH_SYN;
		syn_packet->th_win = htons(ctx->receiver_window_size);

		if (stcp_network_send(sd, syn_packet, sizeof(STCPHeader), NULL) == -1)
		{
			handshake_err_handling(sd);
			return;
		}

		ctx->connection_state = CSTATE_SYN_SENT;

		if(stcp_network_recv(sd, syn_packet, sizeof(STSCPHeader)) < sizeOf(STCPHeader)){
			handshake_err_handling(sd);
			return;
		}
		
		syn_packet->th_flags = TH_ACK;
		ctx->receiver_next_seq = ntohs(syn_packet->th_seq) + 1;
		ctx->sender_next_seq = ntohs(syn_packet->th_ack);
		syn_packet->th_seq = htons(ctx->sender_next_seq);
		syn_packet->th_ack = htons(ctx->receiver_next_seq);
		
		if (stcp_network_send(sd, syn_packet, sizeof(STCPHeader), NULL) == -1)
		{
			handshake_err_handling(sd);
			return;
		}
	}
	else /* Passive end of the connection */
	{
		ctx->connection_state = CSTATE_LISTEN;

		if (stcp_network_recv(sd, syn_packet, sizeof(STCPHeader)) < sizeOf(STCPHeader))
		{
			handshake_err_handling(sd);
			return;
		}
		ctx->connection_state = CSTATE_SYN_RECEIVED;

		ctx->receiver_next_seq = ntohs(syn_packet->th_seq) + 1;
		ctx->sender_window_size = MIN(ntohs(syn_packet->th_win), WINDOW_SIZE);

		/* Next step is to check that SYN flag is set in received header (syn_packet) */
		/* If so, set SYN and ACK flags and send message back to client */
		if(syn_packet->th_flags == TH_SYN){
			syn_packet->th_flags = TH_SYN + TH_ACK;
			syn_packet->th_seq = htons(ctx->sender_next_seq);
			syn_packet->th_ack = htons(ctx->receiver_next_seq);
			if (stcp_network_send(sd, syn_packet, sizeof(STCPHeader), NULL) == -1)
			{
				handshake_err_handling(sd);
				return;
			}
			
			if (stcp_network_recv(sd, syn_packet, sizeof(STCPHeader)) < sizeOf(STCPHeader))
			{
				handshake_err_handling(sd);
				return;
			}
		}else{
			printf("byte order issue");  //Remove before submitting
			handshake_err_handling(sd);
			return;
		}
	}

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
	free(syn_packet);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    /*ctx->initial_sequence_num =;*/
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
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv(), stcp_network_send */		
        }

		else if (event & NETWORK_DATA)
		{
			/* the application is receiving data from the network */
			/* see stcp_app_send(), stcp_network_send */
			/* dependant on ctx->state (conditional logic needed to handle particular connection states) */
		}
        
		else if (event & APP_CLOSE_REQUESTED)
		{
			/* the application is requesting that the connection be closed */
			/* see stcp_network_send() */
			/* dependant on ctx->state (conditional logic needed to handle particular connection states) */
		}
    }
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
void our_dprintf(const char *format,...)
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



