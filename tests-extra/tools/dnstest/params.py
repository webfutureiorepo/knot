#!/usr/bin/env python3

'''
This module allows interchanging of running parameters between modules.
'''

import os, shutil

module_path = os.path.dirname(os.path.realpath(__file__))
repo_path = os.path.realpath(os.path.join(module_path, "..", "..", ".."))
build_path = os.environ.get("KNOT_TEST_BUILD_PATH", repo_path)

def repo_binary(name):
    """Get absolute path to a binary in Knot DNS sources."""
    return os.path.join(build_path, name)

def get_binary(env_name, default):
    env = os.environ.get(env_name)
    # Disable.
    if env == "":
        return ""
    # Use new or default value.
    name = env if env else default
    path = shutil.which(name)
    # Notify user that he set wrong binary
    if env and not path:
        print("Binary \'%s\' not found" % name)
        exit(1)
    return path

def get_param(env_name, default):
    env = os.environ.get(env_name)
    # Disable.
    if env == "":
        return ""
    # Use new or default value.
    return env if env else default

# Indication of debug mode (print ERR on stdout).
debug = False

# Number of available loopback addreeses per each IP version
addresses = 1

# Indication of allowed XDP testing
xdp = False

# KNOT_TEST_VALGRIND - valgrind binary if defined.
valgrind_bin = get_binary("KNOT_TEST_VALGRIND", "valgrind")
# KNOT_TEST_VALGRIND_FLAGS - valgrind flags.
valgrind_flags = get_param("KNOT_TEST_VALGRIND_FLAGS",
                           "--leak-check=full --show-leak-kinds=all --track-origins=yes --vgdb=yes --verbose --num-callers=20 --trace-children=yes --trace-children-skip=/usr/*sh,/bin/*sh")
# KNOT_TEST_GDB - gdb binary.
gdb_bin = get_binary("KNOT_TEST_GDB", "gdb")
# KNOT_TEST_VGDB - vgdb binary.
vgdb_bin = get_binary("KNOT_TEST_VGDB", "vgdb")
# KNOT_TEST_LIBTOOL - libtool script.
libtool_bin = get_binary("KNOT_TEST_LIBTOOL", repo_binary("libtool"))
# KNOT_TEST_LIBKNOT - libknot library.
libknot_lib = get_binary("KNOT_TEST_LIBKNOT", repo_binary("src/.libs/libknot.so"))
# KNOT_TEST_KNOT - Knot binary.
knot_bin = get_binary("KNOT_TEST_KNOT", repo_binary("src/knotd"))
# KNOT_TEST_KNOTC - Knot control binary.
knot_ctl = get_binary("KNOT_TEST_KNOTC", repo_binary("src/knotc"))
# KNOT_TEST_KDIG - Digging binary.
kdig_bin = get_binary("KNOT_TEST_KDIG", repo_binary("src/kdig"))
# KNOT_TEST_KEYMGR - Knot key management binary.
keymgr_bin = get_binary("KNOT_TEST_KEYMGR", repo_binary("src/keymgr"))
# KNOT_TEST_KJOURNALPRINT - Knot journal print binary.
kjournalprint_bin = get_binary("KNOT_TEST_KJOURNALPRINT", repo_binary("src/kjournalprint"))
# KNOT_TEST_KNSUPDATE - Knot dynamic DNS update binary.
knsupdate_bin = get_binary("KNOT_TEST_KNSUPDATE", repo_binary("src/knsupdate"))
# KNOT_TEST_KCATALOGPRINT - Knot catalog print binary.
kcatalogprint_bin = get_binary("KNOT_TEST_KCATALOGPRINT", repo_binary("src/kcatalogprint"))
# KNOT_TEST_BIND - Bind binary.
bind_bin = get_binary("KNOT_TEST_BIND", "named")
# KNOT_TEST_BINDC - Bind control binary.
bind_ctl = get_binary("KNOT_TEST_BINDC", "rndc")
# KNOT_TEST_BIND_CHECKCONF - Bind checkconf binary.
bind_checkconf_bin = get_binary("KNOT_TEST_BIND_CHECKCONF", "named-checkconf")

# KNOT_TEST_OUTS_DIR - working directories location.
outs_dir = get_param("KNOT_TEST_OUTS_DIR", "/tmp")

# HOME - tester's home directory for the "knottest-last" symbolic link.
home_dir = get_param("HOME", "/tmp")

# Common data directory (e.g. zone files).
common_data_dir = ""
