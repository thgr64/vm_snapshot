CC=gcc
C2=g++
CFLAGS=-Wall
API=../api/vmsnapshot.c
API2=../api/hashhelper.c

RDOBJ = rawdump.o 
EXEC += rawdump
OBJS += $(RDOBJ)

PDOBJ = printrawdump.o 
EXEC += printrawdump
OBJS += $(PDOBJ)

build: $(EXEC) 

rawdump: $(RDOBJ)
	$(CC) $(API) -o rawdump $(RDOBJ)

printrawdump: $(PDOBJ)
	$(CC) $(API) -o printrawdump $(PDOBJ)

clean:
	rm -f $(OBJS) $(EXEC)
