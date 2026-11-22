#!/bin/bash
cd "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC"
echo "--- installed kdb.h present?"; ls -l /usr/include/kdb.h 2>&1
echo "--- diff of struct _krb5_db_entry_new region (installed vs vendored)"
awk '/typedef struct _krb5_db_entry_new/,/} krb5_db_entry;/' /usr/include/kdb.h > /tmp/inst_struct.txt
awk '/typedef struct _krb5_db_entry_new/,/} krb5_db_entry;/' plugin/kdb.h > /tmp/vend_struct.txt
wc -l /tmp/inst_struct.txt /tmp/vend_struct.txt
diff /tmp/inst_struct.txt /tmp/vend_struct.txt && echo "STRUCT IDENTICAL"
echo "--- offsetof check against installed header"
cat > /tmp/off.c <<'EOC'
#include <stddef.h>
#include <stdio.h>
#include <krb5/krb5.h>
#include <kdb.h>
int main(void){ printf("installed: offsetof princ=%zu sizeof=%zu\n", offsetof(krb5_db_entry, princ), sizeof(krb5_db_entry)); return 0; }
EOC
gcc -I/usr/include/krb5 -o /tmp/off_inst /tmp/off.c $(pkg-config --cflags krb5) 2>&1 | head -5 && /tmp/off_inst
sed 's#<kdb.h>#"/mnt/c/Users/Som Praneeth/Desktop/COMPSEC/plugin/kdb.h"#' /tmp/off.c > /tmp/off2.c
gcc -o /tmp/off_vend /tmp/off2.c $(pkg-config --cflags krb5) 2>&1 | head -5 && sed 's/installed/vendored/' /dev/null; /tmp/off_vend | sed 's/installed/vendored/'
