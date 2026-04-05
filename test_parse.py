#!/usr/bin/env python3
"""test_parse.py — Quick smoke test for all 6 sample files."""
import sys, os
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parser.mms_parser import parse_mms

files = [
    "samples/0.mms",
    "samples/1.mms",
    "samples/2.mms",
    "samples/3.mms",
    "samples/4.mms",
    "samples/5.mms",
]

all_ok = True
for f in files:
    data = open(f, "rb").read()
    try:
        msg = parse_mms(data)
        h = msg.header
        parts = ", ".join(
            f"{p.content_type.mime}({p.size}B)" for p in msg.parts
        )
        typename = h.message_type.name if h.message_type else "?"
        ver = h.mms_version.label if h.mms_version else "?"
        subj = h.subject or "-"
        frm = h.from_addr.value if h.from_addr else "-"
        date = h.date.display if h.date else "-"
        print(f"OK  {f}: type={typename} ver={ver} "
              f"parts={len(msg.parts)}[{parts}] "
              f"subj={subj} from={frm} date={date}")
    except Exception as e:
        print(f"FAIL {f}: {e}")
        import traceback
        traceback.print_exc()
        all_ok = False

if all_ok:
    print("\nALL 6 PASSED")
else:
    print("\nSOME TESTS FAILED")
    sys.exit(1)
