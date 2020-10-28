#!/usr/bin/python
# dispatch.py - CPET server-side receptacle dispatcher 
# RAB 1/05
# TODO:  rewrite the db connection properly, e.g., use psycopg
# support for length as 2nd arg added 12/06
# documentation added 10/2020

### The CPET server Server.java creates a process running this python program dispatch.py
### for each command received from a client.
### Command received either as second command-line argument for this program dispatch.py
### or as standard input for this program dispatch.py (integer 2nd arg)
###     Example commands:
###         <poll />
###         <engage-receptacle type="Scheme" code="(+ 3 4)" />
### This program dispatch.py is responsible for the following:
###    - parse most or all of that received command
###    - if that command does not require a receptacle
###          carry out that command using a handler function, e.g., do_poll()
###      else
###          launch receptacle (e.g., Scheme) to carry out command

import os
import sys
import re
import time
from receptacles.lib import getAttrib

### define key variables shell, tmpdir, command

shell = "/bin/bash"

tmpdir = sys.argv[1]               ### dir for temporary files if needed by a receptacle
arg = sys.argv[2]                  ### second argument, either a command or an integer
#user = sys.argv[3]

if arg[0] == "<":
    command = arg
else:
    # arg holds number of bytes to read from standard input
    command = sys.stdin.read(int(arg))
# command has been retrieved from command-line 

### set some parameters

SESSION_LIFESPAN = 30*60 # number of seconds before a session times out
#SESSION_ID_LENGTH = 30 # number of hex digits in a session ID

# os.environ['PSQL'] ="psql  -d cpet -P format=unaligned  -t" # testing...
os.environ['PGHOST'] = "anansi.cs.stolaf.edu"

#PSQL = "psql  -d cpet -P format=unaligned  -t" # testing...
PSQL = "psql  -d cpet_orig -P format=unaligned  -t" # testing...
PROG = "CPET Server"
receptDir = "receptacles"
tmpQidPrefix = "qtmp"
receptTables = ('cmss', 'services')

### helper function for printing error messages consistently

# heads of error messages from postgres
ERROR_PREFIX = 'CPET_SERVER_ERROR:  '
duplicate_key_error = ERROR_PREFIX + ":  Cannot insert a duplicate key"

def printError(msg):
    print >> sys.stderr, ERROR_PREFIX + msg

### regular-expression patterns for identifying and parsing various kinds of values

urlPat = r"[/:.a-zA-Z0-9_-]*"
qidPat = "(?:" + tmpQidPrefix + ")?" + r"[0-9]*" 
receptPat = r"[a-zA-Z0-9+_.-]*"
versPat = r"[0-9.a-zA-Z_-]*"
valuePat = r"[^;\"']*"
typePat = r"[a-zA-Z-]*"
alphanumPat = r"\w*"
alphanumdashPat = r"[\w\-]*"
annotValuePat = r"[\w%@*/+.-]*"
keywordsPat = r"[\w&@]*"

### helper functions used by command handlers

# create a unique session id
# input - string to use as part of the data used to create the session key.
#         Although not required, it is best if this includes some unique 
#         data from the site, such as it's IP address or other environment 
#         information.  
# From http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/52252, 8/1/05
def makeSessionID(st):
    import string,md5, time, base64
    m = md5.new()
    m.update('this is a test of the emergency broadcasting system')
    m.update(str(time.time()))
    m.update(str(st))
    return string.replace(base64.encodestring(m.digest())[:-3], '/', '.')

def psql(query):
    fi,foe = os.popen4(PSQL + " -F'	'" + ' -c "' + query + '"')
    return foe.read()

def psql_error(message, error):
    return message[0:len(error)] == error

# maintain the session database table
def sessionMaint():
    psql("delete from session where expiration < '" + str(int(time.time())) +
         "'")

### handler functions, one per protocol keyword (e.g., poll or engage-receptacle)

### handler for engage-receptacle protocol keyword
def do_engage_receptacle():
    TYPE=getAttrib('type', typePat, command)  ### type attribute provides receptacle name
    receptCmd = receptDir + "/" + TYPE

    if os.access(receptCmd, os.X_OK):         ### if that receptacle is an executable file
        ### split into two processes
        ###     one ("parent") starts executing the receptacle program in a shell
        ###     the other ("child") continues dispatch.py, to relay results to server
        pipe = os.pipe()
        if os.fork() != 0:
            # parent process
            os.close(0)
            os.dup(pipe[0])
            os.close(pipe[0])
            os.close(pipe[1])
            os.execl(shell, 'CPET', '-c', receptCmd + ' ' + tmpdir)
        else:
            # child process
            os.close(1)
            os.dup(pipe[1])
            os.close(pipe[0])
            os.close(pipe[1])
            print >> sys.stdout, command + "\n"
            sys.exit(0)
    else:
        raise ValueError, "\nUnrecognized receptacle type '" + TYPE + "'"

infoParsePatC = re.compile(r"^before=\?(.*)\?&after=\?(.*)\?$")

def do_process_question():
    global command
    URL=getAttrib('root-url', urlPat, command)
    QID=getAttrib('qid', qidPat, command)

    key = "root_url = '" + URL + "' and qid = '" + QID + "'"
    receptacle = psql("select receptacle from questions where " + key).strip()
    receptCmd = receptDir + "/" + receptacle
    if receptacle != "" and os.access(receptCmd, os.X_OK):
        info = psql("select info from questions where " + key).strip()
        match = infoParsePatC.match(info)
        before,after = match.group(1,2)
        if not command.endswith("/>"):
            raise ValueError, "\nExpected protocol command to end with />"
        # command ends with "/>"
        command = command[0:-2] + ' before="' + before + \
                  '" after="' + after + '"/>'
        fi, foe = os.popen4(receptCmd, 't')
        fi.write(command + "\n")
        fi.close()
        out = foe.read()
        foe.close()
        print out
    else:
        #raise ValueError, "..."
        printError("NON-CPET")

def do_get_parameter():
    global command
    TYPE=getAttrib('type', alphanumPat, command, "???")
    ID=getAttrib('id', alphanumPat, command, "???")
    NAME=getAttrib('name', alphanumPat, command, "???")

    # Limit queries according to user here...
    
    fields = ''
    where = ''
    def processAttrib(attName, attVal, fields, where):
        if attVal == "???":
            if fields != '':
                fields += ', '
            fields += attName
        else:
            if where == '':
                where = 'where '
            else:
                where += 'and '
            where += attName + " = '" + attVal + "' "
        return fields, where
        
    fields, where = processAttrib('type', TYPE, fields, where)
    fields, where = processAttrib('id', ID, fields, where)
    fields, where = processAttrib('name', NAME, fields, where)
    if fields == '':
        fields = 'value'
    else:
        fields += ', value'

    rv = psql('select ' + fields + ' from parameters ' + where)
    if rv == "":
        printError("NO_VALUE")
    else:
        print fields.replace(', ', '\t') + '\n' + rv
    

def do_set_parameter():
    global command
    TYPE=getAttrib('type', alphanumPat, command)
    ID=getAttrib('id', alphanumPat, command)
    NAME=getAttrib('name', alphanumPat, command)
    VALUE=getAttrib('value', valuePat, command)

    # Limit queries according to user here...

    where = "where type = '" + TYPE + "' and id = '" + ID + \
        "' and name = '" + NAME + "'"
    orig = psql('select value from parameters ' + where)
    if orig == "":
        orig = "NO_VALUE"
    retval = psql('insert into parameters ' +
                  '(type, id, name, value) values ' +
                  "('" + TYPE + "','" + ID + "','" + NAME + "','" +
                  VALUE + "')")
    if psql_error(retval, duplicate_key_error):
        psql('update parameters set ' + "value = '" + VALUE + "' " + where)
    print "Prior: " + orig

def do_set_question():
    URL=getAttrib('root-url', urlPat, command)
    QID=getAttrib('qid', qidPat, command)

    label = QID
    NEW_QID = getAttrib('new-qid', qidPat, command, "")
    if NEW_QID != "":
        assert QID != "", 'Attempting <set-question new-qid="..." ...>' \
               ' with empty qid!'
        label += "  " + NEW_QID
        print label + '\n' + \
              psql("select qtmp_to_qid('" + QID + "','" + NEW_QID + "')")
        return
    # assert:  no new-qid attribute

    RECEPT=getAttrib('receptacle', receptPat, command)
    VERS=getAttrib('cpet-version', versPat, command)
    INFO=getAttrib('info', valuePat, command)

    if QID == "":
        # new question from a professor, real QID not yet known
        QID = psql('select get_tmp_qid()').strip()
        label = QID
    assert QID != "", "Error getting a new temporary qid!"

    msg = ""

    psql('begin') # is there a race here?  
    count = psql("select count(*) from questions where root_url = '" + URL +
                 "' and ( qid = '" + QID +
                 "' or other_qid = '" + QID + "')").strip()

    if count == "0":
        msg += psql('insert into questions ' +
                   '(root_url,qid,receptacle,cpet_version,info) values ' +
                   "('" + URL + "','" + QID + "','" + RECEPT + "','" +
                   VERS + "','" + INFO + "')")
    else:
        assert count == "1" or count == "2", \
               "Error:  too many rows in questions database " + \
               "for qid = " + QID + "!"
        msg += psql('update questions set ' + 
                   "receptacle = '" + RECEPT + "', cpet_version = '" + VERS +
                   "', info = '" + INFO +
                   "' where root_url = '" + URL + "' and (qid = '" + QID +
                   "' or other_qid = '" + QID + "')")
    psql('commit')

    print label + "\n" + msg
    
def do_get_question():
    URL=getAttrib('root-url', urlPat, command)
    QID=getAttrib('qid', qidPat, command)

    print psql("select * from questions where qid = '" + QID +
               "' and root_url = '" + URL + "'").strip()

def do_get_receptacles():
    print "DEBUG - entering do_get_receptacles()"
    TYPE=getAttrib('type', typePat, command)
    if TYPE in receptTables:
        print psql("select name from " + TYPE).strip()
    else:
        raise ValueError, "\nUnrecognized receptacle type '" + TYPE + "'"

def do_get_structure():
    RECEPT=getAttrib('receptacle', receptPat, command)
    print psql("select * from cmss where name = '" + RECEPT + "'").strip()

def do_poll():
    print "ACK"

def do_login():
    USER = getAttrib('user', alphanumPat, command)
    PERSISTENT = getAttrib('persistent', alphanumPat, command, "false")
    prefix = "elDoom"
    if PERSISTENT == "true":
        prefix += "1"
    else:
        prefix += "0"
    now = int(time.time())  # integer number of seconds since 1/1/1970
    sessionID = makeSessionID(USER+str(now))
    sessionMaint()
    ret = psql("insert into session values ('" + sessionID + "', '" +
               USER + "', '" + str(now + SESSION_LIFESPAN) + "')")
    if ret.find("INSERT ") == 0:
        print prefix + sessionID
    else:
        raise ValueError, \
              "\nInsertion error in session table---???"

def do_new_session_id():
    OLD_SESSION_ID=getAttrib('old-session-id', valuePat, command)
    sessionMaint()
    user = psql("select usr from session where session_ID = '" +
                OLD_SESSION_ID + "'")
    if (user == ''):
        printError("INVALID SESSION ID")
        return
    # valid session id;  user holds associated username
    
    now = int(time.time())  # integer number of seconds since 1/1/1970
    sessionID = makeSessionID(user+str(now))
    ret = psql("insert into session values ('" + sessionID + "', '" +
               user + "', '" + str(now + SESSION_LIFESPAN) + "')")
    if ret.find("INSERT ") == 0:
        print sessionID
    else:
        raise ValueError, \
              "\nInsertion error in session table---???"

def do_annotate():

    # delimiters for (group, list, keyword, value):
    separators = ('#@#', '$@$', '&@&', '*@*') 
    terminators = ('#!#', '$!$', '&!&', '*!*')
    # names for level indices
    GRP=0
    LIS=1
    KWD=2
    VAL=3
    
    # printTree prints sorted records from annotations table in tree order
    # using delimiters above as per CPET documentation, to a depth of maxLevel
    # records is return from a psql query (delimited by tabs/newlines)
    # minLevel and maxLevel are min/max indexes to use from delimiter arrays
    def printTree(records, minLevel, maxLevel):
        # printRecord prints a record starting at a particular level,
        # omitting an initial separator at that starting level
        def printRecord(names, startLevel):
            level = startLevel
            while level < maxLevel:
                sys.stdout.write(names[level] + terminators[level])
                level += 1
            # level == maxLevel
            sys.stdout.write(names[level])
                
        reclist = records.rstrip().split("\n")
        if reclist == ['']:
            print ""
            return
        currNames = reclist[0].split("\t")
        printRecord(currNames, minLevel)
        reclist = reclist[1:]
        # invar
        #   all records in reclist prior to rec have been printed in tree order
        #   currNames holds array of most recent names encountered at levels 
        #     between minLevel and maxLevel
        for rec in reclist:
            names = rec.split("\t")
            level = minLevel
            while level <= maxLevel and names[level] == currNames[level]:
                level += 1
            # level is first index in which names differs from currNames
            sys.stdout.write(separators[level])
            printRecord(names, level)
            currNames = names
        print
        return        
    
    ACTION=getAttrib('action', alphanumdashPat, command)

    # actions that don't require a session ID

    if ACTION == "get-groups":
        records = psql("select distinct name from ann_groups order by name")
        printTree(records, GRP, GRP)
        return

    elif ACTION == "get-lists":
        GROUP=getAttrib('group', alphanumPat, command, None)
        if GROUP == None:
            records = psql("select distinct g.name as grp, l.name as list " +
                           "from ann_groups g, ann_lists l " +
                           "where g.gid = l.gid order by grp, list")
            printTree(records, GRP, LIS)
        else:  # group was specified
            records = psql("select '" + GROUP + "', name from ann_lists " +
                           "where gid = ann_gid('" + GROUP +"') order by name")
            printTree(records, LIS, LIS)
        return

    # actions that require a session ID

    SESSION_ID=getAttrib('session-id', valuePat, command)
    sessionMaint()
    user = psql("select usr from session where sid = '" + SESSION_ID + "'")\
           .rstrip()
    if (user == ''):
        printError("INVALID SESSION ID")
        return
    # valid session id;  user holds associated username
    
    if ACTION == "get-tree":
        records = psql("select grp, list, keyword, value from annotations " +
                       "order by grp, list, keyword")
        # assert:  no repetitions among records, by uniqueness constraint
        printTree(records, GRP, VAL)


    elif ACTION == "add":
        GROUP=getAttrib('group', alphanumPat, command)
        LIST=getAttrib('list', alphanumPat, command, None)
        KEYWORD=getAttrib('keyword', alphanumPat, command, None)
        VALUE=getAttrib('value', annotValuePat, command, None)
        msg = ""  # accumulated return message

        if not ((KEYWORD == None and VALUE == None) or
                (LIST != None and KEYWORD != None and VALUE != None)):
            raise ValueError, \
                  "\nParse error:  missing attribute(s) for annotate/add"
        # no missing attributes:  (LIST,KEYWORD,VALUE) in {(,,),(*,,),(*,*,*)}

        if psql("select count(*) from ann_groups where name = '" + GROUP +
                "'").strip() == "0":
            ret = psql("insert into ann_groups (name) values ('" + GROUP +"')")
            if ret.find("INSERT ") == 0:
                msg += "group " + GROUP + " " + ret
            else:
                raise ValueError, \
                  "\nInsertion error:  " + \
                  "could not insert a new annotation group " + GROUP
        # assert GROUP exists

        if LIST != None:
            if psql("select count(*) from ann_lists " +
                    "where name = '" + LIST + "' and" + 
                    " gid = ann_gid('" + GROUP + "')").strip() == "0":
                ret = psql("insert into ann_lists (gid, name) " +
                           "values (ann_gid('" + GROUP + "'), '" + LIST + "')")
                if ret.find("INSERT ") == 0:
                    msg += "list " + LIST + " " + ret
                else:
                    raise ValueError, \
                          "\nInsertion error:  could not insert a new " + \
                          "annotation list " + GROUP + "/" + LIST
            # assert LIST exists

        if KEYWORD != None and VALUE != None:
            # assert:  GROUP and LIST were non-None and exist in database
            ret = psql("insert into ann_keywords " +
                       "values (ann_listid('" + GROUP + "', '" +
                       LIST + "'), '" + KEYWORD + "', '" + VALUE + "', null)")
            if ret.find("INSERT ") == 0:
                msg += "keyword " + ret
            else:
                raise ValueError, "\nInsertion error:  " + \
                      "keyword already exists in that list?"
            
        print msg

    elif ACTION == "update":
        GROUP=getAttrib('group', alphanumPat, command)
        LIST=getAttrib('list', alphanumPat, command)
        KEYWORD=getAttrib('keyword', alphanumPat, command)
        VALUE=getAttrib('value', annotValuePat, command)

        ret = psql("update ann_keywords set value = '" + VALUE +
                   "' where listid = ann_listid('" + GROUP + "', '" + LIST +
                   "') and keyword = '" + KEYWORD + "'")
        if ret.find("UPDATE") == 0:
            print ret
        else:
            raise ValueError, \
                  "\nUpdate error:  No such group,list,keyword exists?"


    elif ACTION == "delete":  
        GROUP=getAttrib('group', alphanumPat, command)
        LIST=getAttrib('list', alphanumPat, command, None)
        KEYWORD=getAttrib('keyword', alphanumPat, command, None)

        if LIST == None and KEYWORD == None:   # delete a group
            if psql("select count(*) from ann_lists " +
                    "where gid = ann_gid('" + GROUP + "')").strip() != "0":
                raise ValueError, \
                      "\nDelete error:  group not empty"
            # GROUP is empty or non-existent
            ret = psql("delete from ann_groups " +
                       "where gid = ann_gid('" + GROUP + "')")
            if ret.find("DELETE 1") == 0:
                print ret
            else:
                raise ValueError, \
                      "\nDeletion error:  Nonexistent group?"

        elif KEYWORD == None:   # delete a list
            if psql("select count(*) from ann_keywords " +
                    "where listid = ann_listid('" + GROUP + "', '" + LIST +
                    "')").strip() != "0":
                raise ValueError, \
                      "\nDelete error:  keyword list not empty?"
            # LIST is empty or non-existent
            ret = psql("delete from ann_lists " +
                       "where listid = ann_listid('" + GROUP + "', '" + LIST +
                       "')")
            if ret.find("DELETE 1") == 0:
                print ret
            else:
                raise ValueError, ret + \
                      "\nDeletion error:  Nonexistent keyword list?"

        else:   # delete a keyword
            ret = psql("delete from ann_keywords " + 
                       "where listid = ann_listid('" + GROUP + "', '" + LIST +
                       "') and keyword = '" + KEYWORD +"' and lockid is null")
            if ret.find("DELETE 1") == 0:
                print ret
            else:
                raise ValueError, \
                      "\nDeletion error:  Locked or non-existent keyword?"


    elif ACTION == "user-add":
        GROUP=getAttrib('group', alphanumPat, command)
        LIST=getAttrib('list', alphanumPat, command)

        ret = psql("insert into ann_user_lists " +
                   "values ('" + user + "', ann_listid('" + GROUP + "', '" +
                   LIST + "'))")
        if ret.find("INSERT ") == 0:
            print ret
        else:
            raise ValueError, \
                  "\nInsertion error:  no such list or " + \
                  "list already included in preferences?"


    elif ACTION == "user-delete":
        GROUP=getAttrib('group', alphanumPat, command)
        LIST=getAttrib('list', alphanumPat, command)

        ret = psql("delete from ann_user_lists " +
                   "where usr = '" + user + "' and listid = ann_listid('" +
                   GROUP + "', '" + LIST + "')")
        if ret.find("DELETE 1") == 0:
            print ret
        else:
            raise ValueError, \
                  "\nDeletion error:  No such list present in preferences?"

        
    elif ACTION == "get-user-lists":
        records = psql("select distinct g.name as grp, l.name as list " +
                       "from ann_groups g, ann_lists l " +
                       "where g.gid = l.gid and l.listid in " +
                       "(select u.listid from ann_user_lists u " +
                       " where usr = '" + user + "') " + 
                       "order by grp, list")
        printTree(records, GRP, LIS)


    elif ACTION == "get-user-keywords":
        records = psql("select distinct text(''), text(''), k.keyword " +
                       "from ann_keywords k, ann_user_lists u " +
                       "where u.usr = '" + user + "' and u.listid = k.listid "+
                       "order by k.keyword")
        printTree(records, KWD, KWD)


    elif ACTION == "get-user-values":
        KEYWORDS=getAttrib('keywords', keywordsPat, command).strip()
        sqlList = "('" + KEYWORDS.replace(separators[KWD], "','") + "') "
        records = psql("select distinct text(''), text(''), k.keyword, " +
                       " k.value " +
                       "from ann_keywords k, ann_user_lists u " +
                       "where u.usr = '" + user + "' and " +
                       "u.listid = k.listid and k.keyword in " + sqlList +
                       "order by k.keyword, k.value")
        printTree(records, KWD, VAL)

    else:
        raise ValueError, "\nUnrecognized annotate action"


### main algorithm ###

try:
    regexp = re.compile(r"^<([a-zA-Z0-9_-]+).*>$")      ### verify/parse format of command
    match = regexp.match(command)
    if match == None or match.group(1) == None:
        raise ValueError, "\nMissing/illegal element name or missing >: "
    tag = match.group(1)
    # tag is the XML-style element tag for the protocol keyword
    ### Example:  tag might hold "poll" or "engage-receptacle")
    ### Note to Runestone team:  this regexp checks that > is final character...

    ### call the appropriate handler to complete the work of this program
    if tag == "engage-receptacle":
        do_engage_receptacle()
    elif tag == "get-question":
        do_get_question()
    elif tag == "set-question":
        do_set_question()
    elif tag == "get-parameter":
        do_get_parameter()
    elif tag == "set-parameter":
        do_set_parameter()
    elif tag == "get-receptacles":
        do_get_receptacles()
    elif tag == "get-structure":
        do_get_structure()
    elif tag == "process-question":
        do_process_question()
    elif tag == "poll":
        do_poll()
    elif tag == "login":
        do_login()
    elif tag == "annotate":
        do_annotate()
    elif tag == "new-session-id":
        do_new_session_id()

    else:
        raise ValueError, "\nUnrecognized protocol request type '" + tag + "'"
    
### handle unrecognized protocol keyword here
except ValueError, v:
    printError("Error in protocol query:  " + v.args[0])
    sys.exit(1)
