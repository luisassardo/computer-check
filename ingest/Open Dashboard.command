#!/bin/bash
# Double-click this to update and open the C-LAB ingest dashboard.
#
# 1. Put the .age files users send you into the "inbox" folder (next to this file).
# 2. Double-click this. It decrypts new reports, adds them to cc.db, rebuilds the
#    dashboard, and opens it in your browser.
#
# Re-dropping the same file is safe (de-duped). Old reports stay in cc.db even if
# you remove their files.

cd "$(dirname "$0")" || exit 1

# --- your age PRIVATE key (the one that decrypts submissions) ----------------
# Edit this line if your key file lives somewhere else.
IDENTITY="${CC_IDENTITY:-$HOME/clab-computercheck-identity.txt}"
[ -f "$IDENTITY" ] || IDENTITY="$HOME/clab-identity.txt"
if [ ! -f "$IDENTITY" ]; then
  echo "Could not find your age private key."
  echo "Open this file in a text editor and set IDENTITY to your key path,"
  echo "e.g.  IDENTITY=\"\$HOME/clab-computercheck-identity.txt\""
  echo
  echo "Press any key to close."; read -r -n 1; exit 1
fi

echo "Updating dashboard from inbox/ …"
python3 cc_ingest.py --in inbox --identity "$IDENTITY" --db cc.db --out dashboard.html
status=$?

if [ $status -eq 0 ] && [ -f dashboard.html ]; then
  open dashboard.html
else
  echo
  echo "Something went wrong (exit $status). Check the messages above."
  echo "Press any key to close."; read -r -n 1
fi
