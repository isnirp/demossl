all:
	#gcc -Wall main.c -o main -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto
	gcc -Wall comm_symmetric_channel.c alice.c bob.c main.c -o main -I/usr/local/ssl/include -L/usr/local/ssl/lib -lcrypto -lssl
	#gcc -Wall comm_symmetric_channel.c alice.c main.c -o main -lcrypto
	#gcc -Wall comm_symmetric_channel.c alice.c main.c -o main -I/openssl-1.0.0.a/include/openssl -lcrypto
	
	# gcc test.c -o test -I/usr/local/ssl/include -L/usr/local/ssl/lib -lssl -lcrypto

	
# run:
# 	./main