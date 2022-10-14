//PrintHelloWorld_10.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

void sys_mdelay(unsigned int ms_delay)
{
    usleep(ms_delay*1000);
}

void PrintHelloWorld_10()
{

    //int i = 0;
    int received = 0;

    printf("============== Simple Application Test ==============\n");

    //for(i=0; i<10; i++)
    while(!received)
    {
      printf("Hello World\n");
      sys_mdelay(1000);
    }
}


