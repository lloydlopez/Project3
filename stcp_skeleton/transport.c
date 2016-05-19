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
    tcp_seq receiver_initial_sequence_num;
    
	tcp_seq sender_next_seq;
	tcp_seq receiver_next_seq;

	size_t sender_window_size;
	size_t receiver_window_size;

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

	if (is_active)
	{	
		syn_packet->th_seq = htonl(ctx->sender_next_seq);
		syn_packet->th_flags = TH_SYN;
		syn_packet->th_win = htons(ctx->receiver_window_size);

		if (stcp_network_send(sd, syn_packet, sizeof(TCPHeader), NULL) == -1)
		{
			handshake_err_handling(sd);
			return;
		}

		ctx->connection_state = CSTATE_SYN_SENT;
        


		/* Next step is to to call stcp_network_recv() and wait for the SYNACK */

		/* Afterward, send ACK back to server */
		

	}
	else /* Passive end of the connection */
	{
		ctx->connection_state = CSTATE_LISTEN;
        
        while(ctx->connection_state!=CSTATE_ESTABLISHED)
            {
                    switch(ctx->connection_state)
                    {
                        case CSTATE_LISTEN : break;
                        
                        case CSTATE_SYN_SENT : 
                        
                            syn_header = (STCPHeader *) malloc(HEADER_SIZE);
                            assert(syn_header);
                            memset(syn_header, 0, HEADER_SIZE);

                            /* construct the syn header */
                            syn_header->th_seq   = ctx->initial_sequence_num;
                            syn_header->th_flags = TH_SYN;
                            syn_header->th_win   = htons(ctx->receiver_window_size);
                            
                            /* send SYN */
                            if (stcp_network_send(sd, syn_header, HEADER_SIZE, NULL) == -1)
                                errno = ECONNREFUSED;
                                
                            /* change the connection state */
                            ctx->connection_state = CSTATE_SYN_RECEIVED;

                            break;
                            
                        case CSTATE_SYN_RECEIVED : break;
                        case CSTATE_ESTABLISHED : break;
                        
                        case CSTATE_FIN_WAIT_1 : 
                            
                            stcp_fin_recieved(sd);
                            break;
                            
                        case CSTATE_FIN_WAIT_2 :
                        case CSTATE_CLOSE_WAIT : 
                        case CSTATE_CLOSING : 
                        case CSTATE_LAST_ACK :
                        case CSTATE_TIME_WAIT : 
                    } 
                    }
		if (stcp_network_recv(sd, syn_packet, sizeof(TCPHeader), NULL) < sizeOf(STCPHeader))
		{
			handshake_err_handling(sd);
			return;
		}

		ctx->receiver_next_seq = ntohl(syn_packet->th_seq) + 1;
		ctx->sender_window_size = MIN(ntohs(syn_packet->th_win), WINDOW_SIZE);

		/* Next step is to check that SYN flag is set in received header (syn_packet) */

		/* If so, set SYN and ACK flags and send message back to client */


	}

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
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
        
        tcphdr *hdr;
        hdr = (tcphdr *) calloc(1, sizeof(tcphdr));
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv(), stcp_network_send */		
        }

		else if (event & NETWORK_DATA)
		{   
            char buf[PACKET_SIZE] = {0};
            size_t rcvd = stcp_network_recv(sd, buf, PACKET_SIZE)-HEADER_SIZE;
            memcpy(hdr, buf, HEADER_SIZE);
            hdr = convert_to_host(hdr);
            char data[PACKET_SIZE - HEADER_SIZE] = {0};

            memcpy(data, &(buf[HEADER_SIZE]), rcvd);
            bool_t flag = false;
            switch(connection_state){
              case CSTATE_FIN_WAIT1:
                if(hdr->th_ack-hdr->th_seq == 1){
                  printf("%d %d CSTATE_FIN_WAIT1\n",hdr->th_seq,hdr->th_ack );
                  connection_state = CSTATE_FIN_WAIT2;
                }
                else
                  continue;
                break;
              case CSTATE_FIN_WAIT2:
                if(hdr->th_flags == TH_FIN){
                  stcp_fin_received(sd);
                  flag = true;
                  hdr->th_ack = hdr->th_seq + 1;
                  printf("SEND: %d %d CSTATE_FIN_WAIT2\n",hdr->th_seq, hdr->th_ack );
                  stcp_network_send(sd, (void *)convert_to_network(hdr), sizeof(struct tcphdr), NULL);
                  connection_state = TIMEWAIT;
                }
                else
                  continue;
                break;

              case CSTATE_LAST_ACK:
                if(hdr->th_flags == TH_FIN){
                  stcp_fin_received(sd);
                  flag = true;
                }
                else
                  continue;
                break;
            }      
			/* the application is receiving data from the network */
			/* see stcp_app_send(), stcp_network_send */
			/* dependant on ctx->state (conditional logic needed to handle particular connection states) */
		}
        
		else if (event & APP_CLOSE_REQUESTED)
		{
            if(ctx->connection_state == CSTATE_ESTABLISHED)
            {
                
            }
			/* the application is requesting that the connection be closed */
			/* see stcp_network_send() */
<<<<<<< Updated upstream
			/* dependant on ctx->state (conditional logic needed to handle particular connection states) */
=======
			/* dependant on ctx->state (conditional logic needed to handle connection particular states) */
>>>>>>> Stashed changes
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



