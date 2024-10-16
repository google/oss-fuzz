import os
import sys
import bashlex

from glob import glob


s1="""# build project
autoconf
autoheader
./configure
make -j$(nproc) libhts.a test/fuzz/hts_open_fuzzer.o

# build fuzzers
$CXX $CXXFLAGS -o "$OUT/hts_open_fuzzer" test/fuzz/hts_open_fuzzer.o $LIB_FUZZING_ENGINE libhts.a -lz -lbz2 -llzma -lcurl -lcrypto -lpthread"""

def find_all_bash_scripts_in_src():
    all_scripts = []
    all_scripts = [y for x in os.walk('/src/') for y in glob(os.path.join(x[0], '*.sh'))]
    scripts_we_care_about = []
    to_ignore = {'aflplusplus', 'honggfuzz', '/fuzztest', '/centipede'}
    for s in all_scripts:
        if any([x for x in to_ignore if x in s]):
            continue
        scripts_we_care_about.append(s)
    #for root, subFolder, files in os.walk('/src/'):
    #    for item in files:
    #        if item.endswith(".sh") :
    #            all_scripts.append(item)
    print(scripts_we_care_about)
    return scripts_we_care_about


def should_include_command(ast_tree):
    if 'configure' in ast_tree.parts[0].word:
        return False
    if 'autoheader' in ast_tree.parts[0].word:
        return False
    if 'autoconf' in ast_tree.parts[0].word:
        return False
    if 'cmake' in ast_tree.parts[0].word:
        return False
    
    if len(ast_tree.parts) > 1 and 'make' in ast_tree.parts[0].word and 'clean' in ast_tree.parts[1].word:
        return False
    return True


def is_local_redirection(ast_node, all_scripts):
    #print("Checking")
    if len(ast_node.parts) >= 2:
        if ast_node.parts[0].word == '.':
            suffixes_matching = []
            #print(ast_node.parts[1].word)
            for bash_script in all_scripts:
                #print("- %s"%(bash_script))
                if bash_script.endswith(ast_node.parts[1].word):
                    suffixes_matching.append(bash_script)
            #print(suffixes_matching)
            return suffixes_matching
    return []

def parse_script(bash_script, all_scripts) -> str:
    new_script = ''
    with open(bash_script, 'r', encoding='utf-8') as f:
        build_script = f.read()
    #print(build_script)
    parts = bashlex.parse(build_script)
    for part in parts:
        try:
            if not should_include_command(part):
                continue
        except:
            continue

        matches = is_local_redirection(part, all_scripts)
        if len(matches) == 1:
            new_script += parse_script(matches[0], all_scripts) + '\n'
            continue
        #print(part.dump())
        idx_start = part.pos[0]
        idx_end = part.pos[1]
        new_script += build_script[idx_start:idx_end]
        new_script += '\n'
        #print("[%s]"%(build_script[idx_start:idx_end]))
    return new_script


if __name__ == "__main__":
    all_scripts = find_all_bash_scripts_in_src()
    replay_bash_script = parse_script(sys.argv[1], all_scripts)

    print("REPLAYABLE BASH SCRIPT")
    print("#"*60)
    print(replay_bash_script)
    print("#"*60)