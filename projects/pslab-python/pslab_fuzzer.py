import sys
import atheris
import pslab


def fuzz_i2c(data):
    fdp = atheris.FuzzedDataProvider(data)
    i2c = pslab.I2C()
    try:
        address = fdp.ConsumeIntInRange(0, 127)  # Valid 7-bit I2C addresses
        register = fdp.ConsumeIntInRange(0, 255)  # Register range
        value = fdp.ConsumeIntInRange(0, 255)  # Data to write

        i2c.read(address, register)

        i2c.write(address, register, value)
    except Exception:
        pass


def fuzz_oscilloscope(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        oscilloscope = pslab.instrument.Oscilloscope()

        # Fuzz parameters for capture
        channels = [fdp.ConsumeIntInRange(1, 4) for _ in range(2)]
        timegap = fdp.ConsumeFloat()  # Time gap between captures

        oscilloscope.capture(channels=channels, timegap=timegap)
    except Exception:
        pass


def fuzz_waveform_generator(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        waveform_generator = pslab.waveform_generator.WaveformGenerator()

        frequency = fdp.ConsumeFloatInRange(1.0, 100000.0)  # Frequency in Hz
        amplitude = fdp.ConsumeFloatInRange(0.1, 5.0)  # Amplitude in volts
        waveform_type = fdp.ConsumeString(8)  

        waveform_generator.generate(frequency=frequency, amplitude=amplitude, waveform_type=waveform_type)
    except Exception:
        pass


def TestOneInput(data):
    fuzz_i2c(data)
    fuzz_oscilloscope(data)
    fuzz_waveform_generator(data)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
