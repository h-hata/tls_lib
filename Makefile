OBJ=dump.o tls.o 
LOPT=-L /usr/local/XXX
IOPT=-I /usr/local/YYY
all: tlsrv
tlsrv: $(OBJ) tlsrv.c
	gcc $(LOPT) -Wall -o tlsrv $(OBJ) tlsrv.c -lpthread -lssl -lcrypto
.c.o:
	gcc $(IOPT) -Wall -o $*.o -Wall -DDEBUG -c $<
clean:
	rm -f $(OBJ) tlsrv  a.out tags
