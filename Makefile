all: http-server

http-server: *.cpp
	g++ -g http-server.cpp -o http-server -lssl -lcrypto -lpthread

run-server: *.cpp http-server
	./http-server

clean:
	@rm http-server
