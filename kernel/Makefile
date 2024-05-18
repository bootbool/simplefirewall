ccflags-y = -g -O0

obj-m += simplefirewall.o

simplefirewall-y := ip.o cidr.o procfs.o netfilter.o main.o 

#KDIR := /lib/modules/$(shell uname -r)/build
KDIR = /home/r/Desktop/work/runninglinuxkernel_5.0
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
