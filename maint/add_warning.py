#!/usr/bin/python

import sys
import os
import re
import shutil

PAT = re.compile(r'^#!\[(allow|deny|warn)')

WANT_LINTS = """
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::cargo_common_metadata)]
#![warn(clippy::clone_on_ref_ptr)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
"""
WANT_LINTS = [ "%s\n" % w for w in WANT_LINTS.split() ]

SOON="""
"""

WISH_WE_COULD = """
#![warn(unused_crate_dependencies)]
"""

DECIDED_NOT = """
#![deny(clippy::redundant_pub_crate)]
#![deny(clippy::future_not_send)]
#![deny(clippy::redundant_closure_for_method_calls)]
#![deny(clippy::panic)]
#![deny(clippy::if_then_some_else_none)]
#![deny(clippy::expect_used)]
#![deny(clippy::option_if_let_else)]
#![deny(missing_debug_implementations)]
#![deny(clippy::pub_enum_variant_names)]
"""


PAT2 = re.compile(r'^#!\[(allow|deny|warn)\(((?:clippy::)?)([^\)]*)')
def warning_key(w):
    m = PAT2.match(w)
    return (len(m.group(2)), m.group(3))

def filter_file(lints, inp, outp):
    head,warnings,other = list(),list(),list()
    for line in inp.readlines():
        if line.startswith("//!"):
            head.append(line)
        elif PAT.match(line) :
            warnings.append(line)
        else:
            other.append(line)

    for add_lint in lints:
        if add_lint not in warnings:
            warnings.append(add_lint)
    warnings.sort(key=warning_key)

    while other[0] == '\n':
        del other[0]

    for line in head:
        outp.write(line)
    outp.write("\n")
    for line in warnings:
        outp.write(line)
    outp.write("\n")
    for line in other:
        outp.write(line)

def process(lints, fn):
    print("{}...".format(fn))
    bak_name = fn+".bak"
    outp = open(bak_name,'w')
    inp = open(fn,'r')
    filter_file(lints, inp, outp)
    inp.close()
    outp.close()
    shutil.move(bak_name, fn)

def main(lints,files):
    if not os.path.exists("./crates/tor-proto/src/lib.rs"):
        print("Run this from the top level of an arti repo.")
        sys.exit(1)

    if not files:
        print("No files provided.  Example usage:")
        print("   ./maint/add_warning.py ./maint/add_warning.py crates/*/src/{lib,main}.rs")

    for fn in files:
        process(lints, fn)


if __name__ == '__main__':
    main(WANT_LINTS, sys.argv[1:])
