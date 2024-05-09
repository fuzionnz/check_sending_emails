#! /bin/bash

# Gets a list of all domains in mail.log
#
# Pipeline explained:
# 1) checks mail.log for from lines
# 2) excludes lines without an '@" as these default to fuzion
# 3) strips out the sender part
# 4) removes the trailing '>'
# 5) sort so we can use uniq
# 6) uniq to get us a list of unique domains
grep -E 'from=<[^>]*>' /var/log/mail.log -o | grep -F '@' | sed 's/^from=<[^@]*@//' | sed 's/>$//' | sort | uniq
