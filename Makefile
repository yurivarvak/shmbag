
ifeq ($(PRO_MACHINE_TYPE), x86e_win64)
CC = cl /O2 /Zi /nologo
CPP = cl /EHsc /GS- /GR- /I. /Zi /nologo /O2
OBJEXT = .obj
EXEEXT = .exe
LINKLIBS =
else
CC = gcc -std=gnu99 -O2
CPP = g++ -std=c++11 -I. -O3
OBJEXT = .o
EXEEXT = 
LINKLIBS = -lrt -pthread
endif

all: shmbag$(OBJEXT) test$(OBJEXT) test$(EXEEXT)

shmbag$(OBJEXT): shmbag.cxx
	$(CPP) -o $@ -c $<

test$(OBJEXT): test.cxx
	$(CPP) -o $@ -c $<

testobjs = test$(OBJEXT) shmbag$(OBJEXT)

test$(EXEEXT): $(testobjs)
	$(CPP) -o $@ $(testobjs) $(LINKLIBS)
