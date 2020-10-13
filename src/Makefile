# Makefile for CPET server source
# Started by RAB 1/05

# a server test:  
#  At server:                            At client: 
#  startServer 40001 > & Server.tmp
#                                        setenv CPET_HOST arachne.cs.stolaf.edu
#                                        setenv CPET_PORT 40001
#                                        make tests
#  CTRL-C
#  grep -v 'Thu Jul 21' Server.tmp | diff Server.out - | & more

BIN=../bin
BIN_name=$(shell basename $(BIN))
BU=../bu
#OTHERHOST=cs18.cs.stolaf.edu
#OTHERBIN=/project/cpet/bin
OTHERHOST=cg.cs.stolaf.edu
OTHERBIN=/usr/local/cs/www/cpet/server/bin

BIN_FILES = $(wildcard *.py *.class) startServer cpet receptacles/Scheme \
receptacles/lib.py receptacles/LAML receptacles/__init__.py

%.class:  %.java
	javac $*.java

all: Server.class TestClient2.class # tests.sh tests

pub:
	pub Server.class ClientThread.class

try:
	do_command.sh '<engage-receptacle type="Scheme" code="(define rate 1.9)%0a(string-append %22You%27re pre-approved for a mortgage at only %22%0A               (number->string rate) %22%34!!%22)%0a%22Call now!%22">'

testdir/tests.sh:  testdir/tests.m4
	m4 testdir/tests.m4 > testdir/tests.sh

# INSERTX shows hook for automatic ignoring of INSERT, qtmp and new-qid values
tests:
	@echo "" ; echo "***" Expected diffs:  one INSERT seq number, two qtmp numbers, two new-qid numbers:
	testdir/tests.sh > testdir/tests.tmp 2>&1 ; echo s/INSERTX// | sed -f - testdir/tests.tmp | diff testdir/tests.out -
	cat testdir/tests.subs

out:
	testdir/tests.sh 2>&1 > testdir/tests.out 

install: 
	@NOW="`date +%Y%m%d_%H:%M:%S`" ; TARGET="$(BU)/$(BIN_name)_$$NOW.tar";\
	(cd $(BIN)/.. ; tar cf - $(BIN_name)) > $$TARGET ; \
	echo created $$TARGET
	@for x in $(BIN_FILES) ; \
	do  test $(BIN)/$$x -ot $$x && { \
		echo $$x... ; \
		NEW="$$NEW $$x" ; \
		cp $$x $(BIN)/$$x ; \
		chmod 750 $(BIN)/$$x ; \
		test $$x = dispatch.py && { \
		    echo " " chmod o+rx $(BIN)/dispatch.py ; \
		    chmod o+rx $(BIN)/dispatch.py ; } \
	    } || true ; \
	done ; \
	echo Installing on $(OTHERHOST) ; cd $(BIN) ; tar cf - $$NEW | \
	rsh $(OTHERHOST) cd $(OTHERBIN) \; mv $$NEW old \; tar xvf - \; \
	chmod g+w $$NEW 
