import base64
import mock
import main

mock_context = mock.Mock()
mock_context.event_id = '61273213213'
mock_context.timestamp = '2019-07-15T22:09:03.761Z'

def test_sync(capsys):
	data = {}
	main.sync(data, mock_context)
	out, err = capsys.readouterr()
	print(err)