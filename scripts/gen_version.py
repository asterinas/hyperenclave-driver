#!/usr/bin/python3

def main():
    err_msg = "Invalid version format. Should be va.b.c"
    f = open("./VERSION")
    vstr = f.read()
    if vstr[0] != 'v':
        raise Exception(err_msg)

    subversion_s = vstr[1:].split(".");
    if len(subversion_s) != 3:
        raise Exception(err_msg)

    subversion = list(map(lambda x: int(x), subversion_s))
    version = subversion[0] << 16 | (subversion[1] << 8) | subversion[2]

    print("#define HE_VERSION_SHORT 0x%x" % version)

main()
