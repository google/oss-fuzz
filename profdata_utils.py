import sys

class ProfData:
  def __init__(self, text):
    self.function_profs = []
    for function_prof in text.split('\n\n'):
      if not function_prof:
        continue
      self.function_profs.append(FunctionProf(function_prof))

  def to_string(self):
    return '\n'.join([function_prof.to_string() for function_prof in self.function_profs])

  def find_function(self, function, idx=None):
    if idx is not None:
      possibility = self.function_profs[idx]
      if function.func_hash == possibility.func_hash:
        return possibility
    for function_prof in self.function_profs:
      if function_prof.func_hash == function.func_hash:
        return function_prof

  def subtract(self, subtrahend):
    for idx, function_prof in enumerate(self.function_profs):
      subtrahend_function_prof = subtrahend.find_function(function_prof, idx)
      function_prof.subtract(subtrahend_function_prof)


class FunctionProf:
  FUNC_HASH_COMMENT_LINE = '# Func Hash:'
  NUM_COUNTERS_COMMENT_LINE = '# Num Counters:'
  COUNTER_VALUES_COMMENT_LINE = '# Counter Values:'
  def __init__(self, text):
    print(text)
    lines = text.splitlines()
    try:
      self.function = lines[0]
    except IndexError:
      import ipdb; ipdb.set_trace()
    assert self.FUNC_HASH_COMMENT_LINE == lines[1]
    self.func_hash = lines[2]
    assert self.NUM_COUNTERS_COMMENT_LINE == lines[3]
    self.num_counters = int(lines[4])
    assert self.COUNTER_VALUES_COMMENT_LINE == lines[5]
    self.counter_values = [1 if int(line) else 0 for line in lines[6:]]

  def to_string(self):
    lines = [
        self.function,
        self.FUNC_HASH_COMMENT_LINE,
        self.func_hash,
        self.NUM_COUNTERS_COMMENT_LINE,
        str(self.num_counters),
        self.COUNTER_VALUES_COMMENT_LINE,
    ] + [str(num) for num in self.counter_values]
    return '\n'.join(lines)

  def subtract(self, subtrahend_prof):
    self.counter_values = [max(counter1 - counter2, 0)
                           for counter1, counter2 in
                           zip(self.counter_values, subtrahend_prof.counter_values)]


def main():
  if len(sys.argv) != 4:
    print(f'Usage: {sys.argv[0]} <minuend_file> <subtrahend_file> <difference_file>')
  with open(sys.argv[1]) as minuend_file:
    print('minuend', sys.argv[1])
    minuend = ProfData(minuend_file.read())
  with open(sys.argv[2]) as subtrahend_file:
    subtrahend = ProfData(subtrahend_file.read())
  minuend.subtract(subtrahend)
  print(sys.argv[3])
  with open(sys.argv[3], 'w') as fp:
    fp.write(minuend.to_string())


if __name__ == '__main__':
  main()
