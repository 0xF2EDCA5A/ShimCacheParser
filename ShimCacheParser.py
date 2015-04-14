# ShimCacheParser.py
#
# Andrew Davis, andrew.davis@mandiant.com
# Copyright 2012 Mandiant
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Identifies and parses Application Compatibility Shim Cache entries for forensic data.

import os
import csv
import sys
import struct
import logging
import zipfile
import argparse
import binascii
import datetime
import cStringIO as sio
from os import path
from csv import writer
from optparse import OptionParser
import xml.etree.cElementTree as et

# Values used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
CACHE_MAGIC_NT5_2 = 0xbadc0ffe
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

# Values used by Windows 6.1 (Win7 and Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xbadc0fee
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

# Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xdeadbeef
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

# Values used by Windows 8
WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = '00ts'

# Magic value used by Windows 8.1
WIN81_MAGIC = '10ts'

G_BAD_ENTRY_DATA = 'N/A'
G_VERBOSE = False
G_OUTPUT_HEADER = ["Hostname", "Order", "Last Modified", "Last Update", "Path", "File Size", "Exec Flag",]

# setup logging
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                               '%Y-%m-%d %H:%M:%S')

logfile = logging.FileHandler("%s.log" % os.path.splitext(__file__)[0])
logfile.setLevel(logging.INFO)
logfile.setFormatter(log_format)

stdout = logging.StreamHandler(sys.stdout)
stdout.setLevel(logging.INFO)
stdout.setFormatter(log_format)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.addHandler(logfile)
log.addHandler(stdout)

# Shim Cache format used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
class CacheEntryNt5(object):
    
    def __init__(self, is32bit, data=None):
        
        self.is32bit = is32bit
        if data != None:
            self.update(data)
            
    def update(self, data):
        
        if self.is32bit:
            entry = struct.unpack('<2H 3L 2L', data)
        else:
            entry = struct.unpack('<2H 4x Q 2L 2L', data)
        self.wLength = entry[0]
        self.wMaximumLength =  entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.dwFileSizeLow = entry[5]
        self.dwFileSizeHigh = entry[6]
        
    def size(self):
        
        if self.is32bit:
            return NT5_2_ENTRY_SIZE32
        else:
            return NT5_2_ENTRY_SIZE64
        
# Shim Cache format used by Windows 6.1 (Win7 through Server 2008 R2)
class CacheEntryNt6(object):
    
    def __init__(self, is32bit, data=None):
        
        self.is32bit = is32bit
        if data != None:
            self.update(data)
            
    def update(self, data):
        
        if self.is32bit:
            entry = struct.unpack('<2H 7L', data)
        else:
            entry = struct.unpack('<2H 4x Q 4L 2Q', data)
        self.wLength = entry[0]
        self.wMaximumLength =  entry[1]
        self.Offset = entry[2]
        self.dwLowDateTime = entry[3]
        self.dwHighDateTime = entry[4]
        self.FileFlags = entry[5]
        self.Flags = entry[6]
        self.BlobSize = entry[7]
        self.BlobOffset = entry[8]
        
    def size(self):
        
        if self.is32bit:
            return NT6_1_ENTRY_SIZE32
        else:
            return NT6_1_ENTRY_SIZE64

#########
#Attempt to extract hostname from filename
#########
def get_mir_host_name(file_path):
    """
    Get the host name, host am cert hash, and audit type from the MIR file
    name in the provided file path. MIR audit filenames have the following
    format:

        <HOSTNAME>-<AMCERTHASH>-<HOSTPARTICLEID>-<DOCPARTICLEID>_<audittype>.xml
    """
    file_name = os.path.basename(file_path)

    # use rsplit in event that hostname contains '_'
    file_name_parts = file_name.rsplit('_', 1)
    if len(file_name_parts) != 2:
        return '', ''

    # hostnames may contain '-', so there could be > 4 fields
    fields, audit_type = file_name_parts
    fields = fields.split('-')
    if len(fields) < 4:
        return '', ''

    # if hostname contained '-', rejoin hostname fields
    host_name = '-'.join(fields[:-3] or [])
    host_hash  = fields[-3]

    return (host_name, host_hash)

################
# Usage
################
def usage():
    print \
        """
Input Options:
    -h, --help              Displays this message
    -b, --bin=BIN_FILE      Reads Shim Cache data from a binary BIN_FILE
    -m, --mir=XML           Reads Shim Cache data from a MIR XML file
    -z, --zip=ZIP_FILE      Reads ZIP_FILE containing MIR registry acquisitions
    -i, --hive=REG_HIVE     Reads Shim Cache data from a registry REG_HIVE
    -r, --reg=REG_FILE      Reads Shim Cache data from a .reg Registry export file
    -l, --local             Reads Shim Cache data from local system
Output Options:
    -o, --outfile=FILE      Writes to CSV data to FILE (default is STDOUT)
    -v, --verbose           Toggles verbose output"""

# Convert FILETIME to datetime.
# Based on http://code.activestate.com/recipes/511425-filetime-to-datetime/
def convert_filetime(dwLowDateTime, dwHighDateTime):
    
    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)    
        temp_time = dwHighDateTime
        temp_time <<= 32
        temp_time |= dwLowDateTime
        return date + datetime.timedelta(microseconds=temp_time/10)
    except OverflowError, err:
        return None

# Return a unique list while preserving ordering.
def unique_list(li):
    
    ret_list = []
    for entry in li:
        if entry not in ret_list:
            ret_list.append(entry)
    return ret_list

################
# Write the Log.
################
def write_it(rows, outfile=None, append=False, host_name='N/A', print_header=True):
    global G_OUTPUT_HEADER
    try:
        if not rows:
            log.debug("No data to write...")
            return

        if G_VERBOSE:
            G_OUTPUT_HEADER += ["Key Path"]

        new_rows = [] 
        if print_header:
            new_rows = [G_OUTPUT_HEADER]
            
        for idx, row in enumerate(rows):
            new_rows.append([host_name, idx] + row)

        if outfile == None:
            for row in new_rows:
                log.info(" ".join(["%s" % x for x in row]))
        else:
            try:
                mode = 'wb'
                if append:
                    mode = 'ab'
                writer = csv.writer(file(outfile, mode), delimiter=',')
                writer.writerows(new_rows)
            except IOError, err:
                log.error("Error writing output file: %s" % str(err))
                return
    except UnicodeEncodeError, err:
        log.error("Error writing output file: %s" % str(err))
        return
    
# Read the Shim Cache format, return a list of last modified dates/paths.
def read_cache(cachebin, quiet=False):
    
    if len(cachebin) < 16:
        # Data size less than minimum header size.
        log.error("Cache size less than minimum header size (16)")
        return []
    
    try:        
        # Get the format type
        magic = struct.unpack("<L", cachebin[0:4])[0]
        
        # This is a Windows 2k3/Vista/2k8 Shim Cache format, 
        if magic == CACHE_MAGIC_NT5_2:
            
            # Shim Cache types can come in 32-bit or 64-bit formats. We can
            # determine this because 64-bit entries are serialized with u_int64
            # pointers. This means that in a 64-bit entry, valid UNICODE_STRING
            # sizes are followed by a NULL DWORD. Check for this here.
            test_size = struct.unpack("<H", cachebin[8:10])[0]
            test_max_size = struct.unpack("<H", cachebin[10:12])[0]
            if (test_max_size-test_size == 2 and
                struct.unpack("<L", cachebin[12:16])[0] ) == 0:
                if not quiet:
                    log.debug("Found 64bit Windows 2k3/Vista/2k8 Shim Cache data...")
                entry = CacheEntryNt5(False)
                return read_nt5_entries(cachebin, entry)
                
            # Otherwise it's 32-bit data.
            else:
                if not quiet:
                    log.debug("Found 32bit Windows 2k3/Vista/2k8 Shim Cache data...")
                entry = CacheEntryNt5(True)
                return read_nt5_entries(cachebin, entry)

        # This is a Windows 7/2k8-R2 Shim Cache.    
        elif magic == CACHE_MAGIC_NT6_1:
            test_size = (struct.unpack("<H",
                         cachebin[CACHE_HEADER_SIZE_NT6_1:
                         CACHE_HEADER_SIZE_NT6_1 + 2])[0])
            test_max_size = (struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1+2:
                             CACHE_HEADER_SIZE_NT6_1 + 4])[0])
            
            # Shim Cache types can come in 32-bit or 64-bit formats.
            # We can determine this because 64-bit entries are serialized with
            # u_int64 pointers. This means that in a 64-bit entry, valid
            # UNICODE_STRING sizes are followed by a NULL DWORD. Check for this here. 
            if (test_max_size-test_size == 2 and
                struct.unpack("<L", cachebin[CACHE_HEADER_SIZE_NT6_1+4:
                CACHE_HEADER_SIZE_NT6_1 + 8])[0] ) == 0:
                if not quiet:
                    log.debug("Found 64bit Windows 7/2k8-R2 Shim Cache data...")
                entry = CacheEntryNt6(False)
                return read_nt6_entries(cachebin, entry)
            else:
                if not quiet:
                    log.debug("Found 32bit Windows 7/2k8-R2 Shim Cache data...")
                entry = CacheEntryNt6(True)
                return read_nt6_entries(cachebin, entry)

        # This is WinXP cache data
        elif magic == WINXP_MAGIC32:
            if not quiet:
                log.debug("Found 32bit Windows XP Shim Cache data...")
            return read_winxp_entries(cachebin)
        
        # Check the data set to see if it matches the Windows 8 format.
        elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE+4] == WIN8_MAGIC:
            if not quiet:
                log.debug("Found Windows 8/2k12 Apphelp Cache data...")
            return read_win8_entries(cachebin, WIN8_MAGIC)

        # Windows 8.1 will use a different magic dword, check for it
        elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE+4] == WIN81_MAGIC:
            if not quiet:
                log.debug("Found Windows 8.1 Apphelp Cache data...")
            return read_win8_entries(cachebin, WIN81_MAGIC)

        else:
            log.error("Got an unrecognized magic value of 0x%x... bailing" % magic)
            return []
 
    except (RuntimeError, TypeError, NameError), err:
        log.error("Error reading Shim Cache data: %s" % err)
        return []

# Read Windows 8/2k12/8.1 Apphelp Cache entry formats.
def read_win8_entries(bin_data, ver_magic):
    offset = 0
    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    cache_data = bin_data[WIN8_STATS_SIZE:]

    data = sio.StringIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        # Read in the entry metadata
        # Note: the crc32 hash is of the cache entry data
        magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)

        # Check the magic tag
        if magic != ver_magic:
            raise Exception("Invalid version magic tag found: 0x%x" % struct.unpack("<L", magic)[0])

        entry_data = sio.StringIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack('<H', entry_data.read(2))[0]
        if path_len == 0:
            path = 'None'
        else:
            path = entry_data.read(path_len).decode('utf-16le', 'replace').encode('utf-8')
        
        # Check for package data
        package_len = struct.unpack('<H', entry_data.read(2))[0]
        if package_len > 0:
            # Just skip past the package data if present (for now)
            entry_data.seek(package_len, 1)

        # Read the remaining entry data
        flags, unk_1, low_datetime, high_datetime, unk_2 = struct.unpack('<LLLLL', entry_data.read(20)) 

        # Check the flag set in CSRSS
        if (flags & CSRSS_FLAG):
            exec_flag = 'True'
        else:
            exec_flag = 'False'

        last_mod_date = convert_filetime(low_datetime, high_datetime)
        try:
            last_mod_date = last_mod_date.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            last_mod_date = G_BAD_ENTRY_DATA

        row = [last_mod_date, 'N/A', path, 'N/A', exec_flag]
        entry_list.append(row)

    return entry_list

# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
def read_nt5_entries(bin_data, entry):
    
    try:
        entry_list = []
        contains_file_size = False
        entry_size = entry.size()
        exec_flag = ''
        
        num_entries = struct.unpack('<L', bin_data[4:8])[0]
        if num_entries == 0:
            return []
        
        # On Windows Server 2008/Vista, the filesize is swapped out of this
        # structure with two 4-byte flags. Check to see if any of the values in
        # "dwFileSizeLow" are larger than 2-bits. This indicates the entry contained file sizes.
        for offset in xrange(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size),
                             entry_size):
            
            entry.update(bin_data[offset:offset+entry_size])
            
            if entry.dwFileSizeLow > 3:
                contains_file_size = True
                break
        
        # Now grab all the data in the value.
        for offset in xrange(CACHE_HEADER_SIZE_NT5_2, (num_entries  * entry_size),
                             entry_size):
            
            entry.update(bin_data[offset:offset+entry_size])
        
            last_mod_date = convert_filetime(entry.dwLowDateTime, entry.dwHighDateTime)
            try:
                last_mod_date = last_mod_date.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                last_mod_date = G_BAD_ENTRY_DATA
            path = bin_data[entry.Offset:entry.Offset + entry.wLength].decode('utf-16le', 'replace').encode('utf-8')
            path = path.replace("\\??\\", "")
            
            # It contains file size data.
            if contains_file_size:
                hit = [last_mod_date, 'N/A', path, str(entry.dwFileSizeLow), 'N/A']
                if hit not in entry_list:
                    entry_list.append(hit)
                    
            # It contains flags.
            else:
                # Check the flag set in CSRSS
                if (entry.dwFileSizeLow & CSRSS_FLAG):
                    exec_flag = 'True'
                else:
                    exec_flag = 'False'
                    
                hit = [last_mod_date, 'N/A', path, 'N/A', exec_flag]
                if hit not in entry_list:
                    entry_list.append(hit)
                    
        return entry_list
    
    except (RuntimeError, ValueError, NameError), err:
        log.error("Error reading Shim Cache data: %s..." % err)
        return []
        
# Read the Shim Cache Windows 7/2k8-R2 entry format,
# return a list of last modifed dates/paths.
def read_nt6_entries(bin_data, entry):
    
    try:
        entry_list = []
        exec_flag = ""
        entry_size = entry.size()
        num_entries = struct.unpack('<L', bin_data[4:8])[0]
        
        if num_entries == 0:
            return []
    
        # Walk each entry in the data structure. 
        for offset in xrange(CACHE_HEADER_SIZE_NT6_1,
                             num_entries*entry_size,
                             entry_size):
            
            entry.update(bin_data[offset:offset+entry_size])
            last_mod_date = convert_filetime(entry.dwLowDateTime,
                                             entry.dwHighDateTime)
            try:
                last_mod_date = last_mod_date.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                last_mod_date = 'N/A'
            path = (bin_data[entry.Offset:entry.Offset +
                             entry.wLength].decode('utf-16le','replace').encode('utf-8'))
            path = path.replace("\\??\\", "")
            
            # Test to see if the file may have been executed.
            if (entry.FileFlags & CSRSS_FLAG):
                exec_flag = 'True'
            else:
                exec_flag = 'False'
                
            hit = [last_mod_date, 'N/A', path, 'N/A', exec_flag]
            
            if hit not in entry_list:
                entry_list.append(hit)
        return entry_list
    
    except (RuntimeError, ValueError, NameError), err:
        log.error("Error reading Shim Cache data: %s...' % err")
        return []

# Read the WinXP Shim Cache data. Some entries can be missing data but still
# contain useful information, so try to get as much as we can.
def read_winxp_entries(bin_data):
    
    entry_list = []
    
    try:
        
        num_entries = struct.unpack('<L', bin_data[8:12])[0]
        if num_entries == 0:
            return []
        
        for offset in xrange(WINXP_HEADER_SIZE32,
                             (num_entries*WINXP_ENTRY_SIZE32), WINXP_ENTRY_SIZE32):

            # No size values are included in these entries, so search for utf-16 terminator.
            path_len = bin_data[offset:offset+(MAX_PATH + 8)].find("\x00\x00")
            
            # if path is corrupt, procede to next entry.
            if path_len == 0:
                continue
            path =  bin_data[offset:offset+path_len + 1].decode('utf-16le').encode('utf-8')
            
            # Clean up the pathname.
            path = path.replace('\\??\\', '')
            if len(path) == 0: continue
            
            entry_data = (offset+(MAX_PATH+8))
            
            # Get last mod time.
            last_mod_time = struct.unpack('<2L', bin_data[entry_data:entry_data+8])
            try:
                last_mod_time = convert_filetime(last_mod_time[0],
                                                 last_mod_time[1]).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                last_mod_time = 'N/A'
                
            # Get last file size.
            file_size = struct.unpack('<2L', bin_data[entry_data + 8:entry_data + 16])[0]
            if file_size == 0:
                file_size = G_BAD_ENTRY_DATA
            
            # Get last update time.
            exec_time = struct.unpack('<2L', bin_data[entry_data + 16:entry_data + 24])
            try:
                exec_time = convert_filetime(exec_time[0],
                                             exec_time[1]).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                exec_time = G_BAD_ENTRY_DATA
                
            hit = [last_mod_time, exec_time, path, file_size, 'N/A']
            if hit not in entry_list:
                entry_list.append(hit)
        return entry_list
    
    except (RuntimeError, ValueError, NameError), err:
        log.error("Error reading Shim Cache data %s" % err)
        return []

# Get Shim Cache data from a registry hive.
def read_from_hive(hive):
    out_list = []
    tmp_list = []

    # Check for dependencies.
    try:
        from Registry import Registry
    except ImportError:
        log.error("Hive parsing requires Registry.py... Didn\'t find it, bailing...")
        sys.exit(2)
        
    try:
        reg = Registry.Registry(hive)
    except Registry.RegistryParse.ParseException, err:
        log.error("Error parsing %s: %s" % (hive, err))
        sys.exit(1)
        
    root = reg.root().subkeys()
    for key in root:
        # Check each ControlSet.
        try:
            if 'controlset' in key.name().lower():
                session_man_key = reg.open('%s\\Control\\Session Manager' % key.name())
                for subkey in session_man_key.subkeys():
                    # Read the Shim Cache structure.
                    if ('appcompatibility' in subkey.name().lower() or
                        'appcompatcache' in subkey.name().lower()):
                        bin_data = str(subkey['AppCompatCache'].value())
                        tmp_list = read_cache(bin_data)
                        
                        for row in tmp_list:

                            if G_VERBOSE:
                                row.append(subkey.path())
                            if row not in out_list:
                                out_list.append(row)

        except Registry.RegistryKeyNotFoundException:
            continue
        
    if len(out_list) == 0:
        return []
    else:
        # if not verbose, attempt to make list unique
        if not G_VERBOSE:
            out_list = unique_list(out_list)

        return out_list
            
# Get Shim Cache data from MIR registry output file.
def read_mir(xml_file, quiet=False):
    out_list = []
    tmp_list = []
    
    # Open the MIR output file.
    try:   
        for (_, reg_item) in et.iterparse(xml_file, events=('end',)):
            if reg_item.tag != 'RegistryItem':
                continue
            
            path_name = reg_item.find("Path").text
            if not path_name:
                log.error("Error XML missing Path")
                print et.tostring(reg_item)
                reg_item.clear()
                continue

            path_name = path_name.lower()

            # Check to see that we have the right registry value.
            if 'control\\session manager\\appcompatcache\\appcompatcache' in path_name \
                or 'control\\session manager\\appcompatibility\\appcompatcache' in path_name:

                # return the base64 decoded value data.
                bin_data = binascii.a2b_base64(reg_item.find('Value').text)
                tmp_list = read_cache(bin_data, quiet)
               
                for row in tmp_list:

                    if G_VERBOSE:
                        row.append(path_name)

                    if row not in out_list:
                        out_list.append(row)

            reg_item.clear()
                    
    except (AttributeError, TypeError, IOError),  err:
        log.error("Error reading MIR XML: %s" % str(err))
        return []
    
    if len(out_list) == 0:
        return []
    else:
        # if not verbose, attempt to make list unique
        if not G_VERBOSE:
            out_list = unique_list(out_list)

        return out_list
        
# Get Shim Cache data from .reg file.
# Finds the first key named "AppCompatCache" and parses the
# Hex data that immediately follows. It's a brittle parser,
# but the .reg format doesn't change too often.
def read_from_reg(reg_file, quiet=False):
    out_list = []

    if not path.exists(reg_file):
        return []
    
    f = open(reg_file, 'rb')
    file_contents = f.read()
    f.close()
    try:
        file_contents = file_contents.decode('utf-16')
    except:
        pass #.reg file should be UTF-16, if it's not, it might be ANSI, which is not fully supported here.

    if not file_contents.startswith('Windows Registry Editor'):
        log.error("Unable to properly decode .reg file: %s" % reg_file)
        return []

    path_name = None
    relevant_lines = []
    found_appcompat = False
    appcompat_keys = 0
    for line in file_contents.split("\r\n"):
        if '\"appcompatcache\"=hex:' in line.lower():
            relevant_lines.append(line.partition(":")[2])
            found_appcompat = True
        elif '\\appcompatcache]' in line.lower() or '\\appcompatibility]' in line.lower():
            # The Registry path is not case sensitive. Case will depend on export parameter.
            path_name = line.partition('[')[2].partition(']')[0]
            appcompat_keys += 1
        elif found_appcompat and "," in line and '\"' not in line:
            relevant_lines.append(line)
        elif found_appcompat and (len(line) == 0 or '\"' in line):
            # begin processing a block
            hex_str = "".join(relevant_lines).replace('\\', '').replace(' ', '').replace(',', '')
            bin_data = binascii.unhexlify(hex_str)
            tmp_list = read_cache(bin_data, quiet)

            for row in tmp_list:
                if G_VERBOSE:
                    row.append(path_name)
                if row not in out_list:
                    out_list.append(row)

            # reset variables for next block
            found_appcompat = False
            path_name = None
            relevant_lines = []
            break

    if appcompat_keys <= 0:
        log.error("Unable to find value in .reg file: %s" % reg_file)
        return []

    if len(out_list) == 0:
        return []
    else:
        # Add the header and return the list.
        if not G_VERBOSE:
            out_list = unique_list(out_list)

        return out_list

# Acquire the current system's Shim Cache data.
def get_local_data():
    
    tmp_list = []
    out_list = []
    global G_VERBOSE    

    try:
        import _winreg as reg
    except ImportError:
        log.error("\'winreg.py\' not found... Is this a Windows system?")
        sys.exit(1)
        
    hReg = reg.ConnectRegistry(None, reg.HKEY_LOCAL_MACHINE)
    hSystem = reg.OpenKey(hReg, r'SYSTEM')
    for i in xrange(1024):
        try:
            control_name = reg.EnumKey(hSystem, i)
            if 'controlset' in control_name.lower():
                hSessionMan = reg.OpenKey(hReg,
                                          'SYSTEM\\%s\\Control\\Session Manager' % control_name)
                for i in xrange(1024):
                    try:
                        subkey_name = reg.EnumKey(hSessionMan, i)
                        if ('appcompatibility' in subkey_name.lower()
                            or 'appcompatcache' in subkey_name.lower()):
                            
                            appcompat_key = reg.OpenKey(hSessionMan, subkey_name)
                            bin_data = reg.QueryValueEx(appcompat_key,
                                                        'AppCompatCache')[0]
                            tmp_list = read_cache(bin_data)
                            if tmp_list:
                                path_name = 'SYSTEM\\%s\\Control\\Session Manager\\%s' % (control_name, subkey_name)
                                for row in tmp_list:
                                    if G_VERBOSE:
                                        row.append(path_name)
                                    if row not in out_list:
                                        out_list.append(row)
                    except EnvironmentError:
                        break
        except EnvironmentError:
            break
        
    if len(out_list) == 0:
        return None
    else:
        #Add the header and return the list.
        if not G_VERBOSE:
            out_list = unique_list(out_list)

        return out_list

# Read a MIR XML zip archive.
def read_zip(zip_name, output_file, processed_hosts):
    
    zip_contents = []
    tmp_list     = []
    final_list   = []
    out_list     = []
    files_parsed = 0
    
    try:
        # Open the zip archive.
        archive = zipfile.ZipFile(zip_name)
        for zip_file in archive.infolist():
            zip_contents.append(zip_file.filename)
        
        log.info("Processing %d registry acquisitions..." % len(zip_contents))
        for item in zip_contents:
            try:
                if '_w32registry.xml' not in item:
                    continue

                host_name, host_hash = get_mir_host_name(item)
                if host_hash in processed_hosts:
                    log.warning("Skipping duplicate host %s (%s)" % (host_name, host_hash))
                    continue

                xml_file = archive.open(item)
                
                # Catch possibly corrupt MIR XML data.
                try:
                    out_list = read_mir(xml_file, quiet=True)
                except(struct.error, et.ParseError), err:
                    log.error("Error reading XML data from host: %s, data looks corrupt. Continuing..." % hostname)
                    continue

                #Add the hostname to the entry list.
                if len(out_list) == 0:
                    log.warning("Processing failed for '%s'. No Shim Cache entries found." % (item))
                    continue
                else:
                    files_parsed += 1
                    write_it(out_list, 
                             output_file, 
                             append       = (files_parsed > 1), 
                             host_name    = host_name, 
                             print_header = (files_parsed == 1))
                    
                xml_file.close()

            except IOError, err:
                log.error("Error opening file: %s in MIR archive: %s" % (item, err))
                continue

        return processed_hosts
        
    except (IOError, zipfile.BadZipfile, struct.error), err:
        log.error("Error reading zip archive: %s" % zip_name)
        return processed_hosts

# Do the work.
def main():
    
    global G_VERBOSE
    
    dscr  = "Parses Application Compatibilty Shim Cache data"
    usage = "\r\n\t%prog -[lbmzir] <input_file_or_dir> -o <output_file>"

    parser = OptionParser(usage=usage, description=dscr)
   
    parser.add_option("-l", "--local",    action="store_true", help="Reads data from local system")
    parser.add_option("-b", "--bin",      default=None,        help="Reads data from a binary BIN file (or dir of BIN files)")
    parser.add_option("-m", "--mir",      default=None,        help="Reads data from a MIR XML file (or dir of MIR XML files)")
    parser.add_option("-z", "--zip",      default=None,        help="Reads ZIP file containing MIR registry acquisitions (or dir of MIR ZIP files)")
    parser.add_option("-i", "--hive",     default=None,        help="Reads data from a registry reg HIVE (or dir of HIVE files)")
    parser.add_option("-r", "--reg",      default=None,        help="Reads data from a .reg registry export file")
    parser.add_option("-n", "--hostname", default=None,        help="Manually specify the hostname to include in the output file")
    parser.add_option("-o", "--out",      dest='output_file',  help="Writes to CSV data to FILE (default is STDOUT)")
    parser.add_option("-v", "--verbose",  action="store_true", help="Include registry key path in output")
    parser.add_option("-d", "--debug",    action="store_true", help="Toggles debug output messages")

    (options, args) = parser.parse_args()

    if options.verbose:
        G_VERBOSE = True

    if options.debug:              
        log.setLevel(logging.DEBUG)      
        logfile.setLevel(logging.DEBUG)
        stdout.setLevel(logging.DEBUG)

    # Read the local Shim Cache data from the current system
    if options.local:
        log.info("Dumping Shim Cache data from the current system...")
        entries = get_local_data()
        if not entries:
            log.error("No Shim Cache entries found...")
        else:
            write_it(entries, options.output_file)
    else:

        input_path = options.bin or options.mir or options.zip or options.hive or options.reg
        if not input_path:
            parser.error('You must specify the type of file(s) to process.')

        # parse input path, which can be a directory or a file
        file_paths = set()
        append = False
        if os.path.isdir(input_path):
            for root, dirs, files in os.walk(input_path):
                log.debug("Found directory '%s'" % root)
                file_paths.update(map(lambda f: os.path.join(root, f), files))
    
            append = True
        else:
            file_paths.add(input_path)

        # count of files parsed and unique hosts
        files_parsed = 0
        processed_hosts = set()

        # loop over input paths
        for file_path in file_paths:

            # Pull Shim Cache MIR XML.
            if options.mir:
                log.info("Reading MIR output XML file: %s..." % file_path)
                host_name, host_hash = get_mir_host_name(file_path)

                if host_hash in processed_hosts:
                    log.warning("Skipping duplicate host %s (%s)" % (host_name, host_hash))
                    continue

                try:
                    with file(file_path, 'rb') as xml_data:
                        entries = read_mir(xml_data)
                        if len(entries) <= 0:
                            log.error("No Shim Cache entries found...")
                        else:
                            files_parsed += 1
                            processed_hosts.update((host_hash,))
                            write_it(entries, 
                                     options.output_file, 
                                     append       = (files_parsed > 1), 
                                     host_name    = host_name, 
                                     print_header = (files_parsed == 1))

                except IOError, err:
                    log.error("Error opening binary file: %s" % str(err))
        
            # Process a MIR XML ZIP archive
            elif options.zip:
                log.info("Reading MIR XML zip archive: %s..." % file_path)
                entries = read_zip(file_path, options.output_file, processed_hosts)
                
            # Read the binary file.
            elif options.bin:
                log.info("Reading binary file: %s..." % file_path)
                try:
                    with file(file_path, 'rb') as bin_data:
                        bin_data = bin_data.read()
                except IOError, err:
                    log.error("Error opening binary file: %s" % str(err))
                    continue

                entries = read_cache(bin_data)
                if len(entries) == 0:
                    log.error("No Shim Cache entries found...")
                else:
                    write_it(entries, options.output_file, append)
                
            # Read the key data from a registry hive.
            elif options.reg:
                log.info("Reading .reg file: %s..." % file_path)
                entries = read_from_reg(file_path)
                if len(entries) == 0:
                    log.error("No Shim Cache entries found...")
                else:
                    write_it(entries, options.output_file, append)
                    
            elif options.hive:
                log.info("Reading registry hive: %s..." % file_path)
                try:
                    entries = read_from_hive(file_path)
                    if len(entries) == 0:
                        log.error("No Shim Cache entries found...")
                    else:
                        write_it(entries, options.output_file, append)

                except IOError, err:
                    log.error("Error opening hive file: %s" % str(err))
                    continue

if __name__ == '__main__':
    main()