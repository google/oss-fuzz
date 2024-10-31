import os
import sys
import bashlex

from glob import glob


def find_all_bash_scripts_in_src():
  all_scripts = [
      y for x in os.walk('/src/') for y in glob(os.path.join(x[0], '*.sh'))
  ]
  scripts_we_care_about = []
  to_ignore = {'aflplusplus', 'honggfuzz', '/fuzztest', '/centipede'}
  for s in all_scripts:
    if any([x for x in to_ignore if x in s]):
      continue
    scripts_we_care_about.append(s)

  print(scripts_we_care_about)
  return scripts_we_care_about


def should_discard_command(ast_tree) -> bool:
  """Returns True if the command shuold be avoided, otherwise False"""
  try:
    first_word = ast_tree.parts[0].word
  except:  # pylint: disable=bare-except
    return False
  if 'configure' in first_word:
    return True
  if 'autoheader' in first_word:
    return True
  if 'autoconf' in first_word:
    return True
  if 'autoreconf' in first_word:
      return True
  if 'cmake' in first_word:
    return True
  if 'autogen.sh' in first_word:
    return True

  try:
    second_word = ast_tree.parts[1].word
  except:  # pylint: disable=bare-except
    return False

  if 'make' in first_word and 'clean' in second_word:
    return True

  return False


def is_local_redirection(ast_node, all_scripts):
  """Return the list of scripts corresponding to the command, in case
    the command is an execution of a local script."""
  # print("Checking")

  # Capture local script called with ./random/path/build.sh

  if len(ast_node.parts) >= 2:
    try:
      ast_node.parts[0].word
    except:
      return []
    if ast_node.parts[0].word == '.':
      suffixes_matching = []
      #print(ast_node.parts[1].word)
      for bash_script in all_scripts:
        #print("- %s"%(bash_script))
        cmd_to_exec = ast_node.parts[1].word.replace('$SRC', 'src')
        if bash_script.endswith(cmd_to_exec):
          suffixes_matching.append(bash_script)
      #print(suffixes_matching)
      return suffixes_matching
  # Capture a local script called with $SRC/random/path/build.sh
  if len(ast_node.parts) >= 1:
    if '$SRC' in ast_node.parts[0].word:
      suffixes_matching = []
      print(ast_node.parts[0].word)
      for bash_script in all_scripts:
        print("- %s" % (bash_script))
        cmd_to_exec = ast_node.parts[0].word.replace('$SRC', 'src')
        if bash_script.endswith(cmd_to_exec):
          suffixes_matching.append(bash_script)
      print(suffixes_matching)
      return suffixes_matching

  return []


def handle_ast_command(ast_node, all_scripts_in_fs, raw_script):
  """Generate bash script string for command node"""
  new_script = ''
  if should_discard_command(ast_node):
    return ''

  matches = is_local_redirection(ast_node, all_scripts_in_fs)
  if len(matches) == 1:
    new_script += parse_script(matches[0], all_scripts_in_fs) + '\n'
    return ''

  # Extract the command from the script string
  idx_start = ast_node.pos[0]
  idx_end = ast_node.pos[1]
  new_script += raw_script[idx_start:idx_end]
  #new_script += '\n'

  # If mkdir is used, then ensure that '-p' is provided, as
  # otherwise we will run into failures. We don't have to worry
  # about multiple uses of -p as `mkdir -p -p -p`` is valid.
  new_script = new_script.replace('mkdir', 'mkdir -p')
  return new_script


def handle_ast_list(ast_node, all_scripts_in_fs, raw_script):
  new_script = ''
  try_hard = 1

  if not try_hard:
    list_start = ast_node.pos[0]
    list_end = ast_node.pos[1]
    new_script += raw_script[list_start:list_end]  # + '\n'
  else:
    # This is more refined logic. Ideally, this should work, but it's a bit
    # more intricate to get right due to e.g. white-space between positions
    # and more extensive parsing needed. We don't neccesarily need this
    # level of success rate for what we're trying to achieve, so am disabling
    # this for now.
    for part in ast_node.parts:
      if part.kind == 'list':
        new_script += handle_ast_list(part, all_scripts_in_fs, raw_script)
      elif part.kind == 'command':
        new_script += handle_ast_command(part, all_scripts_in_fs, raw_script)
      else:
        idx_start = part.pos[0]
        idx_end = part.pos[1]
        new_script += raw_script[idx_start:idx_end]
      new_script += ' '

  # Make sure what was created is valid syntax, and otherwise return empty
  try:
    bashlex.parse(new_script)
  except:  # pylint: disable=bare-except
    # Maybe return the original here instead of skipping?
    return ''
  return new_script


def handle_ast_compound(ast_node, all_scripts_in_fs, raw_script):
  new_script = ''
  try_hard = 1
  list_start = ast_node.pos[0]
  list_end = ast_node.pos[1]
  new_script += raw_script[list_start:list_end] + '\n'
  return new_script


def handle_node(ast_node, all_scripts_in_fs, build_script):
  """Generates a bash script string for a given node"""
  if ast_node.kind == 'command':
    return handle_ast_command(ast_node, all_scripts_in_fs, build_script)
  elif ast_node.kind == 'list':
    return handle_ast_list(ast_node, all_scripts_in_fs, build_script)
  elif ast_node.kind == 'compound':
    print('todo: handle compound')
    return handle_ast_compound(ast_node, all_scripts_in_fs, build_script)
  elif ast_node.kind == 'pipeline':
    # Not supported
    return ''
  else:
    raise Exception(f'Missing node handling: {ast_node.kind}')


def parse_script(bash_script, all_scripts) -> str:
  """Top-level bash script parser"""
  new_script = ''
  with open(bash_script, 'r', encoding='utf-8') as f:
    build_script = f.read()
  try:
    parts = bashlex.parse(build_script)
  except:
    return ''
  for part in parts:
    new_script += handle_node(part, all_scripts, build_script)
    new_script += '\n'
    print("-" * 45)
    print(part.kind)
    print(part.dump())

  return new_script


if __name__ == "__main__":
  all_scripts = find_all_bash_scripts_in_src()
  replay_bash_script = parse_script(sys.argv[1], all_scripts)

  print("REPLAYABLE BASH SCRIPT")
  print("#" * 60)
  print(replay_bash_script)
  print("#" * 60)
  with open('/out/replay-build-script.sh', 'w') as f:
    f.write(replay_bash_script)
