# assign2


This is an explorative attempt on implementating a server - client pseudo connection via the openssl tool.


server.c 
Is holding the server side by opening a listener on a specific port number and awaiting requests.
Server must be run only as a sudo/root user. Therefore calling with the sudo command is necessary.

By accomodating requests the server after it is accepting a connection, it will verify it according to the specific certifications.




client.c
a client is called with a specific address/hostname of a server and on its port on which he wants to connect.
He attempts a connection by sending request on which he provides information- username-password and of he is certified
he is connected.

In this implementation username/pass are given on fail connections.















#Guided 
