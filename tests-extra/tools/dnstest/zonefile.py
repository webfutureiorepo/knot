#!/usr/bin/env python3

import os
import random
import re
import shutil
import string
import zone_generate
import glob
import dns.name

from subprocess import DEVNULL, PIPE, Popen
from dnstest.utils import *
from dnstest.keys import Keymgr

class ZoneFile(object):
    '''A zone file handler.'''

    def __init__(self, file_dir):
        prepare_dir(file_dir)
        self.file_dir = file_dir
        self.key_dir = os.path.join(file_dir, "keys")
        self.file_name = ""
        self.name = ""

        # Directory containing source zone file/updates.
        self.storage = None

        self.backup_num = 1

    @property
    def path(self):
        '''Get absolute path of the zone file.'''

        return os.path.join(self.file_dir, self.file_name)

    @property
    def key_dir_bind(self):
        '''Path to legacy BIND keys.'''
        return os.path.join(self.key_dir, "bind")

    def set_name(self, name=None):
        '''Set specified or generate zone name.'''

        if name:
            self.name = name
            if self.name[-1] != ".":
                self.name += "."
        else:
            self.name = zone_generate.main(["-n", 1]).strip()

    def set_file(self, file_name=None, storage=None, version=None, exists=True):
        '''Make a copy of an existing zone file. If no file name is specified,
           the file name is constructed from the zone name (zname.zone).
           If version is specified, file_name.version is used.
           The storage is a directory containing the zone file.'''

        if not file_name:
            file_name = self.name + "zone"
        self.file_name = os.path.basename(file_name)

        if not self.storage:
            self.storage = storage if storage else os.path.dirname(file_name)

        if not exists:
            return

        try:
            if os.path.isabs(file_name):
                src_file = file_name
            else:
                src_file = os.path.join(self.storage, self.file_name)

            if version:
                src_file += "." + str(version)

            shutil.copyfile(src_file, self.path)

        except:
            raise Exception("Can't use zone file '%s'" % src_file)

    def upd_file(self, file_name=None, storage=None, version=None):
        '''Replace zone file with a different one.'''

        self.set_file(file_name=file_name, storage=storage, version=version)

    def gen_file(self, dnssec=None, nsec3=None, records=None, serial=None, ttl=None):
        '''Generate zone file.'''

        if dnssec == None:
            dnssec = random.choice([True, False])
        if nsec3 == None:
            nsec3 = random.choice([True, 0, False])
        if not records:
            records = random.randint(1, 200)
        if not serial:
            serial = random.randint(1, 4294967295)

        self.file_name = self.name + "rndzone"

        try:
            params = ["-i", serial, "-o", self.path, "-c", records, self.name]
            if dnssec:
                prepare_dir(self.key_dir_bind)
                params = ["-s", "-3", "n" if nsec3 is False else "y" if nsec3 else "0",
                          "-k", self.key_dir_bind] + params
            if ttl is not None:
                params = [ "-t", str(ttl) ] + params
            if zone_generate.main(params) != 0:
                raise OSError

        except OSError:
            raise Exception("Can't create zone file '%s'" % self.path)

    def dnssec_verify(self, bind_check=True, ldns_check=True):
        '''Call dnssec-verify on the zone file.'''

        check_log("DNSSEC VERIFY for %s (%s)" % (self.name, self.path))

        if bind_check:
            # note: convert origin to lower case due to a bug in dnssec-verify
            origin = self.name.lower()
            cmd = Popen(["dnssec-verify", "-z", "-o", origin, self.path],
                        stdout=PIPE, stderr=PIPE, universal_newlines=True)
            (out, err) = cmd.communicate()

            if cmd.returncode != 0:
                set_err("DNSSEC VERIFY")
                detail_log(" <dnssec-verify>\n" + err.strip())
                self.backup()
            else:
                detail_log(" <dnssec-verify>\n" + err.strip())

        if ldns_check:
            cmd = Popen(["ldns-verify-zone", self.path],
                        stdout=PIPE, stderr=PIPE, universal_newlines=True)
            (out, err) = cmd.communicate()

            if cmd.returncode != 0:
                set_err("LDNS VERIFY")
                detail_log(" <ldns-verify-zone>\n" + err.strip())
                self.backup()
            else:
                detail_log(" <ldns-verify-zone>\n" + out.strip())

        detail_log(SEP)

    def clone(self, file_dir, exists=True):
        '''Make a copy of the zone file.'''

        new = ZoneFile(file_dir)
        new.set_name(self.name)
        new.set_file(file_name=self.path, storage=self.storage,
                     exists=exists and os.path.isfile(self.path))
        return new

    def enable_nsec3(self, salt="abcdef", iters=2):
        '''Insert NSEC3PARAM record to the zone file.'''

        with open(self.path, "a") as file:
            file.write("@ 0 NSEC3PARAM 1 0 %i %s\n" % (iters, salt))

        self.update_soa()

    def disable_nsec3(self):
        '''Remove NSEC3PARAM record if any.'''

        old_name = self.path + ".old"
        os.rename(self.path, old_name)

        with open(old_name) as old_file, open(self.path, 'w') as new_file:
            for line in old_file:
                if not "NSEC3PARAM" in line:
                    new_file.write(line)

        os.remove(old_name)

        self.update_soa()

    def backup(self):
        '''Make a backup copy of the actual zone file.'''

        try:
            shutil.copyfile(self.path, self.path + ".back" + str(self.backup_num))
            self.backup_num += 1
        except:
            raise Exception("Can't make a copy of zone file '%s'" % self.path)

    def get_soa_serial(self):
        with open(self.path, 'r') as f:
            for line in f:
                if "SOA" in line:
                    return int(line.split()[-5])

    def update_soa(self, serial=None, refresh=None, retry=None, expire=None,
                   minimum=None):
        '''Update SOA rdata numbers (serial, timers). The serial is just
           incremented if not specified.'''

        old_name = self.path + ".old"
        os.rename(self.path, old_name)

        first = False

        with open(old_name) as old_file, open(self.path, 'w') as new_file:
            for line in old_file:
                if "SOA" in line and not first:
                    items = line.split()

                    old_serial = int(items[-5])
                    items[-5] = str(serial) if serial else str(old_serial + 1)

                    if refresh:
                        items[-4] = str(refresh)
                    if retry:
                        items[-3] = str(retry)
                    if expire:
                        items[-2] = str(expire)
                    if minimum:
                        items[-1] = str(minimum)

                    new_file.write(str.join(" ", items))
                    new_file.write("\n")
                    first = True
                else:
                    new_file.write(line)

        os.remove(old_name)

    def update_rnd(self):
        '''Add random records or re-sign zone.'''

        dnssec = False
        nsec3 = False

        self.update_soa()

        old_name = self.path + ".old"
        os.rename(self.path, old_name)

        with open(old_name, 'r') as old_file:
            for line in old_file:
                if "RRSIG" in line:
                    dnssec = True
                if "NSEC3PARAM" in line:
                    nsec3 = True

        try:
            params = ["-u", old_name, "-o", self.path, self.name]
            if dnssec:
                prepare_dir(self.key_dir_bind)
                params = ["-s", "-3", "y" if nsec3 else "n", "-k", self.key_dir_bind] \
                         + params
            zone_generate.main(params)
        except OSError:
            raise Exception("Can't modify zone file '%s'" % self.path)

        os.remove(old_name)

    def append_rndAAAA(self, owner, rnd1=random.randint(1, 65000), rnd2=random.randint(1, 65000)):
        '''Append AAAA record with owner owner and random IPv6'''

        with open(self.path, "a") as file:
            file.write("%s IN AAAA dead:beef:dead:beef:dead:beef:%04x:%04x\n" %
                       (owner, rnd1, rnd2))

    def append_rndTXT(self, owner, rdata=None, rdlen=None):
        '''Append random or specified TXT record'''

        if rdata is None:
            if rdlen is None:
                rdlen = random.randint(1, 255)
            rdata = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(rdlen))

        with open(self.path, "a") as file:
            file.write("%s IN TXT %s\n" % (owner, rdata))

    def gen_rnd_ddns(self, ddns, allow_ns=True):
        '''Walk zonefile, randomly mark some records to be removed by ddns and some added'''

        skip_types = ["SOA", "RRSIG", "DNSKEY", "DS", "CDS", "CDNSKEY", "NSEC", "NSEC3", "NSEC3PARAM"]
        if not allow_ns:
            skip_types += ["NS"]

        changes = 0
        with open(self.path, 'r') as file:
            for fline in file:
                line = fline.split(None, 4)
                if len(line) < 3:
                    continue
                if line[0][0] not in [";", "@"]:
                    dname = line[0]
                    ttl = 0
                    if line[1].isnumeric():
                        ttl = line[1]
                        del line[1]
                    if line[1] == "IN":
                        del line[1]
                    rtype = line[1]
                    rdata = ' '.join(line[2:])
                    if rtype not in skip_types:
                        try:
                            if random.randint(1, 20) in [4, 5]:
                                ddns.delete(dname, rtype)
                                origin = dns.name.Name.to_text(ddns.upd.origin)
                                if not (dname == origin and rtype in ["NS"]):          # RFC 2136, Section 7.13
                                    changes += 1
                            prefix = "xyz."
                            if random.randint(1, 20) in [2, 3] and rtype not in ["DNAME", "TYPE39"] and \
                               len(dname) <= 254 - len(prefix):
                                ddns.add(prefix+dname, ttl, rtype, rdata)
                                changes += 1
                        except (dns.rdatatype.UnknownRdatatype, dns.name.LabelTooLong, dns.name.NameTooLong, ValueError, dns.exception.SyntaxError):
                            # problems - simply skip. This is completely stochastic anyway.
                            pass
        return changes

    def count(self, rrtype):
        '''WARNING works well only if zone file is properly flushed by Knot'''
        res = 0
        with open(self.path, 'r') as file:
            for fline in file:
                line = fline.split(None, 4)
                if len(line) < 3 or line[0][0] in [";", "@"]:
                    continue
                if line[2] == rrtype:
                    res = res + 1
        return res

    def check_count(self, expected, rrtype):
        found = self.count(rrtype)
        if found != expected:
            set_err("ZONEFILE RR COUNT")
            check_log("ERROR: ZONEFILE RR COUNT")
            detail_log("!Invalid RR count type=%s zonefile=%s %d!=%d" % (
                rrtype, self.name, found, expected
            ))
            detail_log(SEP)

    def remove(self):
        '''Remove zone file.'''

        try:
            os.remove("%s/%s" % (self.file_dir, self.file_name))
        except:
            pass

