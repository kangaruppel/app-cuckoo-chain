EXEC = cuckoo.out

OBJECTS = \
	main.o \

BOARD ?= mspts430
CONFIG_EDB ?= 0
CONFIG_PRINTF_LIB ?= libmspconsole
CONFIG_LIBEDB_PRINTF ?= bare

LIBCHAIN_ENABLE_DIAGNOSTICS ?= 0

include $(MAKER_ROOT)/Makefile.clang
include $(MAKER_ROOT)/Makefile.board
include $(MAKER_ROOT)/Makefile.console
include $(MAKER_ROOT)/Makefile.edb

CFLAGS += \
	-I $(LIBCHAIN_ROOT)/src/include \
	-I $(LIBEDB_ROOT)/src/include \
	-I $(WISP_BASE_ROOT) \
	-I $(WISP_BASE_ROOT)/Sensors \
	-I $(WISP_BASE_ROOT)/wired \

ifeq ($(LIBCHAIN_ENABLE_DIAGNOSTICS),1)
CFLAGS += -DLIBCHAIN_ENABLE_DIAGNOSTICS
endif

LLVM_LIBS += \
	$(LIBCHAIN_ROOT)/bld/clang/libchain.a.bc \
	$(LIBMSPMATH_ROOT)/bld/clang/libmspmath.a.bc \

CFLAGS += \
	-I$(WISP_BASE_ROOT) \
	-I$(LIBMSP_ROOT)/src/include \
	-I$(LIBMSPMATH_ROOT)/src/include \

LFLAGS += \
	-L$(LIBMSPBUILTINS_ROOT)/bld/gcc \
	-L$(WISP_BASE_ROOT)/gcc \

LIBS += \
	-lmspbuiltins \

VPATH = ../../src
