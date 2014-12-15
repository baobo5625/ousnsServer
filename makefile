ousns_server: ousns_server.o ousns_communicate.o md5.o
	g++ -o ousns_server -L/usr/lib/mysql -lmysqlclient -lpthread `xml2-config --libs` ousns_server.o ousns_communicate.o md5.o
ousns_server.o:
	g++ -c ousns_server.cpp -I/usr/include/mysql `xml2-config --cflags`
ousns_communicate.o:
	g++ -c ousns_communicate.cpp
md5.o:
	g++ -c md5.cpp
clean:
	rm ousns_server.o ousns_communicate.o md5.o ousns_server
