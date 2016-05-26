# Project3
STCP Implementation 

Group Members : Dhruv Seth, James Baracca, John Hager, Lloyd Lopez

Design Logic 
---------------------------------------------------------
 
The transport layer was designed by following the guidelines provided in RFC 793 & RFC 1122.
     
The 11 connection states are defined as enums to be used by Context struct.
 
The flow control is handled by different loops. 
 
transport_init() handles the initialization of the connection & three way handshaking, 
and then jumps to the control loop.
 
The control loop handles most of the sTCP logic. The function
continuously loops, waiting for incoming network data, outgoing data passed 
down from the app, or a close request from the app. It handles each of these
in turn, using IF-ELSE statements the corresponding event type, and also responsible
for making sure the appropriate ACKs are sent and received.

A new function clear_header is used to set all the parameters of TCP Header to zero.

The important metadata for the connection is stored in a context_t struct, which
is global to the thread. It keeps track of whether or not the connection has 
completed by using a boolean variable (done), the enum status of the connection 
(connection_state), the initial generated sequence number for the local side 
(initial_sequence_num). These are useful for getting the correct position in the buffer.
It also maintains the sender's and receiver's next sequence number.
It also keeps track of the sequence number that are currently unacknowledged by receiver. 
The last elements are the unsigned integers which are used to store the sender's window size buffer
(sender_window_size) and receiver's window size (receiver_window_size).

Reading and writing into the buffer is determined by taking the received 
sequence number and subtracting the inital sequence number. This reframes
the data so it's on a 0...N scale. After that, taking the modulus with the 
window size gives the appropriate index in the buffer.
