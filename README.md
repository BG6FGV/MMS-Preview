# mms-reader

A browser-based MMS binary file viewer. Double-click `launch.py` to open.

## Quick Start

```bash
python launch.py
```

A browser window opens at `http://127.0.0.1:5820`. Drop any `.mms` file to inspect it.

## Features

- Parses MMS PDU binary format (WAP 2.3 / OMA MMS Encapsulation v1.2 & v1.3)
- Extracts headers, attachments, SMIL layout
- Renders images, video, audio inline
- Displays text and HTML content
- Visualizes SMIL presentation timeline
- Zero dependencies (Python 3.6+ stdlib only)

## Project Structure

```
mms-reader/
  launch.py              Entry point (double-click to run)
  domain/                Domain entities & value objects
    entities.py          MmsMessage, MmsHeader, MmsPart, SmilPresentation
    value_objects.py     Address, ContentType, MmsTimestamp
  parser/                Binary protocol parser
    mms_parser.py        Top-level parse facade
    mms_header_parser.py MMS PDU header field parser (v1.2/v1.3 auto-detect)
    mms_body_parser.py   WAP multipart body + SMIL parser
    wsp_codec.py         WSP binary primitives (ByteStream, uintvar, Content-Type tables)
  server/                HTTP application
    app.py               Server bootstrap
    config.py            Configuration
    routes.py            Request handlers + part cache
  web/
    index.html           Single-page browser UI
  samples/               Test .mms files from MMS Compiler v1.0
  test_parse.py          Smoke test script
```

## References

- OMA-MMS-ENC-V1_2-20050301-A - MMS Encapsulation Protocol
- OMA-TS-MMS-ENC-V1_3-20080128-C - MMS Encapsulation (v1.3 revision)
- WAP-230-WSP-20010705-a - Wireless Session Protocol (WSP)
- 3GPP TS 23.140 - MMSE architecture
- 3GPP TS 26.140 - Media formats and codecs

## License

BSD 3-Clause. See LICENSE.

MMS Compiler sample files (samples/*.mms) are copyright (c) 2018-2024 Thales,
also licensed under BSD 3-Clause. Original: https://kamenar.com/mms/
