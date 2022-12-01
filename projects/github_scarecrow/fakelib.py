import requests
RAN_ONCE = False

def do_something(data):
    global RAN_ONCE
    if not RAN_ONCE:
        print(requests.get('https://google.com'))
        RAN_ONCE = True
    if not data:
        return
    if data[0]:
        print('hi')
    else:
        print('bye')
