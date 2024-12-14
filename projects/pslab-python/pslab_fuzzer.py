import sys
import atheris
from PSLab import interfaces, experiment, hardware

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    try:
        experiment.set_gain(fdp.ConsumeInt(4))  # Fuzz gain settings
        hardware.analog_read(fdp.ConsumeInt(4))  # Fuzz analog reading
        interfaces.send_data(fdp.ConsumeBytes(8))  # Fuzz data transmission
    except Exception:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
