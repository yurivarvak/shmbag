
ifeq ($(PRO_MACHINE_TYPE), x86e_win64)
CC = cl /O2 /Zi
CPP = cl  /EHsc /I. /Zi
OBJEXT = .obj
EXEEXT = .exe
LINKLIBS =
else
CC = gcc -std=gnu99 -O2
CPP = g++ -std=c++11 -I. -I../boost_1_64_0 -O3
OBJEXT = .o
EXEEXT = 
LINKLIBS = -lrt -pthread
endif

all: shmbag$(OBJEXT) test$(OBJEXT) test$(EXEEXT)

shmbag$(OBJEXT): shmbag.cxx
	$(CPP) -o $@ -c $<

test$(OBJEXT): test.cxx
	$(CPP) -o $@ -c $<

test$(EXEEXT): test$(OBJEXT)
	$(CPP) -o $@ $< shmbag$(OBJEXT) $(LINKLIBS)
