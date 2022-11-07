CC 	   = gcc

CFLAGS = -Wall -Wextra -ggdb

TARGET_S = mydhcps
TARGET_C = mydhcpc

SRCS_S   = mydhcps.c mydhcps_list.c
OBJS_S   = mydhcps.o mydhcps_list.o

SRCS_C   = mydhcpc.c
OBJS_C   = mydhcpc.o

RM 	   = rm -f

all : $(TARGET_S) $(TARGET_C)

$(TARGET_S) : $(OBJS_S)
	$(CC) $(CFLAGS) -o $@ $^

$(TARGET_C) : $(OBJS_C)
	$(CC) $(CFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -c $<

mydhcps.o: mydhcp.h mydhcps.h mydhcps_list.h util.h

mydhcps_list.o: mydhcps_list.h

mydhcpc.o: mydhcp.h mydhcpc.h util.h

clean:
	$(RM) $(TARGET_S) $(TARGET_C) $(OBJS_S) $(OBJS_C)

clean_target:
	$(RM) $(TARGET_S) $(TARGET_C)

clean_obj:
	$(RM) $(OBJS_S) $(OBJS_C)
