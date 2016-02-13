#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int
main(int argc, char* argv[])
{
  int i, j;
  int numzones, zonesize, numhosts, numdelegations, numinsecuredelegations, numsecuredelegations;
  double delegationfraction, optoutfraction;
  FILE *fp = NULL;
  char fname[1024];
  if(!strcmp(argv[1],"-")) {
    numzones = -1;
  } else {
    numzones = strtol(argv[1],NULL,10);
  }
  zonesize = strtol(argv[2],NULL,10);
  delegationfraction = strtod(argv[3],NULL);
  optoutfraction = strtod(argv[4],NULL);
  numdelegations = round(zonesize * delegationfraction);
  numhosts = zonesize - numdelegations;
  numinsecuredelegations = round(numdelegations * optoutfraction);
  numsecuredelegations = numdelegations - numinsecuredelegations;
  for(i=0; i<numzones || (numzones==-1 && i==0); i++) {
    sprintf(fname, "z%d", (numzones==-1?zonesize:i));
    if(numzones != -1) {
      fp = fopen(fname, "w");
    } else {
      fp = stdout;
    }
    fprintf(fp,"$ORIGIN z%d.\n$TTL 60\nz%d. 600 IN SOA ns1. postmaster.z%d. 1000 1200 180 1209600 3600\n",(numzones==-1?zonesize:i),(numzones==-1?zonesize:i),(numzones==-1?zonesize:i));
    for(j=0; j<numhosts; j++) {
      fprintf(fp,"a%d IN A 127.0.0.1\n",j);
    }
    for(j=0; j<numsecuredelegations; j++) {
      //fprintf(fp,"b%d IN NS 127.0.0.1\nb%d IN DS 0\n",j,j);
      fprintf(fp,"example-voorbeeld%d IN NS ns%d.example.nl\nexample-voorbeeld%d IN DS 12345 8 2 deadbeefcafebabebabecafefeebdeedaabbccddeeff112233445566778899ab\n",j,j,j);
    }
    for(j=0; j<numinsecuredelegations; j++) {
      fprintf(fp,"c%d IN NS 127.0.0.1\n",j);
    }
    if(numzones != -1) {
      fclose(fp);
    }
  }
  if(numzones != -1) {
    for(;;) {
      sprintf(fname, "z%d", i);
      if(remove(fname))
        break;
      i++;
    }
  }
  exit(0);
}
