import zipfile
from hashlib import md5

"""
simple, temporary script to dynamically generate a text protocol corpus
for fuzzing memcached text protocol
"""

commands = ["ms $PATH$ $PAYLEN$ $FLAG$ $PAYLOAD$", 
            "mg $PATH$ $FLAG$", 
            "md $PATH$ $FLAG$",
            "ma $PATH$ $FLAG$", 
            "mn ", 
            "set $PATH$ 2 0 2 $PAYLOAD$", 
            "get $PATH$", 
            "add $PATH$ 2 0 2 $PAYLOAD$", 
            "replace $PATH$ 2 0 2 $PAYLOAD$", 
            "append $PATH$ $PAYLEN$ $PAYLOAD$", 
            "prepend $PATH$ $PAYLEN$ $PAYLOAD$", 
            "gets $PATH$", 
            "delete $PATH$", 
            "incr $PATH$ 1",
            "decr $PATH$ 1", 
            "touch $PATH$ 0", 
            "gat 0 $PATH$", 
            "gats 0 $PATH$", 
            "watch", 
            "version", 
            "stats"]

# hardcode these for now
PATH="/foo/test"
PAYLOAD="hi"
PAYLEN="2"
FLAG="c k"

# generate fuzzer_proxy corpus
fproxy_corpus = "fuzzer_proxy_seed_corpus.zip"
with zipfile.ZipFile(fproxy_corpus, "w") as zfile:
    for command in commands:
        data = (command.replace
            ("$PATH$", PATH)
            .replace
            ("$FLAG$", FLAG)
            .replace
            ("$PAYLEN$", PAYLEN)
            .replace
            ("$PAYLOAD$", "\r\n{0}".format(PAYLOAD))) 
        
        zfile.writestr(md5(data.encode("utf-8")).hexdigest(), data)
