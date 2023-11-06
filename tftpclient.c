#include<stdio.h>

#define ASSERT(_bool, ...) do{if (!(_bool)) fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE);}while(0);