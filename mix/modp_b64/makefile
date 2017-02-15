all:main

main:modp_b64.o main.o __random.o
	gcc -o main main.o modp_b64.o __random.o
__random.o:__random.c
	gcc -c __random.c
main.o:main_test_b64.c
	gcc -c main_test_b64.c -o main.o
modp_b64.o: modp_b64.cc modp_b64.h modp_b64_data.h
	gcc -c modp_b64.cc
