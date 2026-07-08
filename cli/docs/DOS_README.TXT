FKT Signer - DOS / 486 Floppy Build
===================================

Files on the 1.44 MB floppy
---------------------------
  FKTSIGNER.EXE   Main signer (interactive menu UI)
  CWSDPMI.EXE     DPMI server (required by DJGPP programs)
  README.TXT      This file (copy of docs/DOS_README.TXT)

Hardware requirements
---------------------
  - 486 or better (80386+ with DPMI)
  - 8 MB RAM minimum (large static PSBT buffers)
  - VGA display for QR output (mode 13h, 320x200)
  - PS/2 or serial keyboard

Boot and run
------------
  1. Boot FreeDOS (or MS-DOS 6.x) from floppy or hard disk.
  2. Insert the FKT floppy and:  A:
  3. Run:  FKTSIGNER.EXE
  4. Use the on-screen menu to load seed, load PSBT, preview, and sign.

PSBT files
----------
  Place .psbt files on the same drive or enter a full path (e.g. C:\TX.PSBT).
  Relative paths are resolved from the current directory and the EXE directory.

QR display
----------
  Signed PSBT QR codes use VGA graphics (not ANSI terminal). Press any key
  after viewing to return to the text menu.

Building from source (Linux host)
---------------------------------
  scripts/bootstrap_djgpp.sh          # once: install cross-compiler
  cd cli && make -f Makefile.dos      # produces FKTSIGNER.EXE
  ../scripts/check_floppy_size.sh FKTSIGNER.EXE
  ../scripts/dosbox_smoke.sh FKTSIGNER.EXE

Copy CWSDPMI.EXE from your DJGPP installation (bin/cwsdpmi.exe) onto the
floppy alongside FKTSIGNER.EXE.

Security notes
--------------
  - Release DOS build has no dev harness (no hex-seed argv, no FKT_NO_CONFIRM).
  - Seed and PSBT material are zeroed on Ctrl+C / SIGINT.
  - Keep the machine offline. Verify addresses on a separate device before signing.