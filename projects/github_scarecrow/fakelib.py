
RAN_ONCE = False

def do_something(data):
    global RAN_ONCE
    if not RAN_ONCE:
        RAN_ONCE = True
    if not data:
        return
    if data[0]:
        print('hi')
    else:
        print('bye')
