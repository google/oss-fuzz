### Pre-requisites

```sh
# Install the required packages.
sudo apt install python3-pip python3-venv
sudo pip3 install virtualenv

# Create virtualenv and install dependencies.
python3 -m venv ENV
source ENV/bin/activate
pip3 install -r requirements.txt
```

### Presubmit

```sh
# Run formatter.
yapf -i *.py

# Run lint checker.
pylint *.py
```
