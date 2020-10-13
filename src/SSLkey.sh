#!/bin/sh
# Steps for creating an RSA key for SSL with Java server
# Run this script in the directory in which keystores should be stored
# Following instructions in Sun's JSSE Ref Guide, 
# java.sun.com/j2se/1.4.2/docs/guide/security/jsse/JSSERefGuide.html#CreateKeystore
# RAB 8/05
PROG=`basename $0`
USAGE="Usage:  $PROG projname [daysofvalidity]"
# e.g., PROG cpet 1800

KEYTOOL=$JAVA_HOME/bin/keytool

DAYS=100
test $# -ge 1 -a -n "$1" || { echo "$USAGE" ; exit 1 ; }
PROJ=$1
test -n "$2" && DAYS=$2
# PROJ, DAYS defined

$KEYTOOL -genkey -alias ${PROJ} -keyalg RSA -validity $DAYS -keystore ${PROJ}.keystore
echo "Public and private keys generated, placed in ${PROJ}.keystore" ; echo ""

echo "Examine keystore contents:"
$KEYTOOL -list -v -keystore ${PROJ}.keystore
echo -n "Continue? (y|n)[y]:  " ; read ANS 
case "$ANS" in ""|Y|y) ;; *) exit 0 ;; esac

$KEYTOOL -export -alias ${PROJ} -keystore ${PROJ}.keystore -rfc -file ${PROJ}.cer
echo "Certificate exported into file ${PROJ}.cer, public key only" ; echo ""

echo "Examine certificate:"
cat ${PROJ}.cer
echo -n "Continue? (y|n)[y]:  " ; read ANS 
case "$ANS" in ""|Y|y) ;; *) exit 0 ;; esac

$KEYTOOL -import -alias ${PROJ}cert -file ${PROJ}.cer -keystore ${PROJ}.truststore
echo "Certificate imported to truststore ${PROJ}.truststore" ; echo ""

echo Examine truststore contents:
$KEYTOOL -list -v -keystore ${PROJ}.truststore
echo ""; echo "Note:  Use keystore in server, truststore in client "
echo "  in order to authenticate server to the client"

