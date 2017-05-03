EXEC = cuckoo_rsa

OBJECTS = \
	cuckoo.o \

DEPS += \
	libchain \
	libmsp \
	libwispbase \
	libio \
  libmspmath \

CONFIG_EDB ?= 0
#CONFIG_PRINTF_LIB ?= libedb
CONFIG_PRINTF_LIB ?= libmspconsole
#CONFIG_LIBEDB_PRINTF ?= eif
include $(MAKER_ROOT)/Makefile.console

export LIBMSP_DCO_FREQ = 8000000
