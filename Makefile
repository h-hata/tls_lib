OBJ=dump.o tls.o 
all: tlsrv
tlsrv: $(OBJ) tlsrv.c
	gcc -o tlsrv $(OBJ) tlsrv.c -lpthread -lssl -lcrypto
.c.o:
	gcc -o $*.o -Wall -DDEBUG -c $<
#	gcc -Wall  -c $<
clean:
	rm -f $(OBJ) tlsrv  a.out tags
