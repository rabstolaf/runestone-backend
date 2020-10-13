"shared functions, objects, etc., for receptacles"

import re

# extracts attribute value for name from string str
# if values does not match pat or attrib name not found, then
#   return noMatch, or throw ValueError if noMatch == "ValueError"
def getAttrib(name, pat, str, noMatch = "ValueError"):
    regexp = re.compile(r"^.* " + name + '="(' + pat + r')".*$')
    match = regexp.match(str)
    if match != None and match.group(1) != None:
        return match.group(1)
    # no match was found
    if noMatch == "ValueError":
        raise ValueError, "Missing or illegal value for attribute '" + \
              name+"'"   + "\n pat=" + pat + "\n str=" + str
    else:
        return noMatch



