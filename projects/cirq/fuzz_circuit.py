#!/usr/bin/python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

import atheris
import sys
import cirq


@atheris.instrument_func
def TestOneInput(data):
    """Fuzzing target for Cirq circuit operations."""
    fdp = atheris.FuzzedDataProvider(data)

    # Test basic circuit creation
    circuit = cirq.Circuit()

    # Generate random number of qubits
    num_qubits = fdp.ConsumeIntInRange(1, 3)
    qubits = cirq.LineQubit.range(num_qubits)

    # Generate random number of operations
    num_ops = fdp.ConsumeIntInRange(1, 5)

    for _ in range(num_ops):
        if not fdp.remaining_bytes():
            break

        # Choose random gate type
        gate_type = fdp.ConsumeIntInRange(0, 5)

        if gate_type == 0 and len(qubits) >= 1:
            # Single qubit X gate
            qubit_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            circuit.append(cirq.X(qubits[qubit_idx]))

        elif gate_type == 1 and len(qubits) >= 1:
            # Single qubit Y gate
            qubit_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            circuit.append(cirq.Y(qubits[qubit_idx]))

        elif gate_type == 2 and len(qubits) >= 1:
            # Single qubit Z gate
            qubit_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            circuit.append(cirq.Z(qubits[qubit_idx]))

        elif gate_type == 3 and len(qubits) >= 1:
            # Hadamard gate
            qubit_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            circuit.append(cirq.H(qubits[qubit_idx]))

        elif gate_type == 4 and len(qubits) >= 2:
            # CNOT gate
            control_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            target_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            if control_idx != target_idx:
                circuit.append(cirq.CNOT(qubits[control_idx], qubits[target_idx]))

        elif gate_type == 5 and len(qubits) >= 2:
            # CZ gate
            control_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            target_idx = fdp.ConsumeIntInRange(0, len(qubits) - 1)
            if control_idx != target_idx:
                circuit.append(cirq.CZ(qubits[control_idx], qubits[target_idx]))

    simulator = cirq.Simulator()
    simulator.simulate(circuit)

def main():
    """Main entry point for the fuzzer."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
