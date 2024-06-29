CC=gcc
TARGET = server client

all: $(TARGET)

server: server.o
	 $(CC) -Wall -o server server.c -L/usr/lib -lssl -lcrypto

client: client.o
	$(CC)  -Wall -o client  client.c -L/usr/lib -lssl -lcrypto

clean:
	$(RM) $(TARGET)
	$(RM) -f .*txt *.o 

