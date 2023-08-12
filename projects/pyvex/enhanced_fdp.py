"""
Defines the EnhancedFuzzedDataProvider
"""
from contextlib import contextmanager
from enum import Enum
from io import BytesIO, StringIO
from tempfile import NamedTemporaryFile
from typing import Optional, Union

from atheris import FuzzedDataProvider


class EnhancedFuzzedDataProvider(FuzzedDataProvider):
    """
    Extends the functionality of FuzzedDataProvider
    """

    def _consume_random_count(self) -> int:
        """
        :return: A count of bytes that is strictly in range 0<=n<=remaining_bytes
        """
        return self.ConsumeIntInRange(0, self.remaining_bytes())

    def _consume_file_data(self, all_data: bool, as_bytes: bool) -> Union[bytes, str]:
        """
        Consumes data for a file
        :param all_data: Whether to consume all remaining bytes from the buffer
        :param as_bytes: Consumed output is bytes if true, otherwise a string
        :return: The consumed output
        """
        if all_data:
            file_data = self.ConsumeRemainingBytes() if as_bytes else self.ConsumeRemainingString()
        else:
            file_data = self.ConsumeRandomBytes() if as_bytes else self.ConsumeRandomString()

        return file_data

    def ConsumeRandomBytes(self) -> bytes:
        """
        Consume a 'random' count of the remaining bytes
        :return: 0<=n<=remaining_bytes bytes
        """
        return self.ConsumeBytes(self._consume_random_count())

    def ConsumeRemainingBytes(self) -> bytes:
        """
        :return: The remaining buffer
        """
        return self.ConsumeBytes(self.remaining_bytes())

    def ConsumeRandomString(self) -> str:
        """
        Consume a 'random' length string, excluding surrogates
        :return: The string
        """
        return self.ConsumeUnicodeNoSurrogates(self._consume_random_count())

    def ConsumeRemainingString(self) -> str:
        """
        :return: The remaining buffer, as a string without surrogates
        """
        return self.ConsumeUnicodeNoSurrogates(self.remaining_bytes())

    def PickValueInEnum(self, enum):
        return self.PickValueInList([e.value for e in enum])

    @contextmanager
    def ConsumeMemoryFile(self, all_data: bool, as_bytes: bool) -> Union[BytesIO, StringIO]:
        """
        Consumes a file-like object, that resides entirely in memory
        :param all_data: Whether to populate the file with all remaining data or not
        :param as_bytes: Whether the file should hold bytes or strings
        :return: The in-memory file
        """
        file_data = self._consume_file_data(all_data, as_bytes)
        file = BytesIO(file_data) if as_bytes else StringIO(file_data)
        yield file
        file.close()

    @contextmanager
    def ConsumeTemporaryFile(self, all_data: bool, as_bytes: bool, suffix: Optional[str] = None) -> str:
        """
        Consumes a temporary file, handling its deletion
        :param all_data: Whether to populate the file with all remaining data or not
        :param as_bytes: Whether the file should hold bytes or strings
        :param suffix: A suffix to use for the generated file, e.g. 'txt'
        :return: The path to the temporary file
        """
        file_data = self._consume_file_data(all_data, as_bytes)
        mode = 'w+b' if as_bytes else 'w+'
        tfile = NamedTemporaryFile(mode=mode, suffix=suffix)
        tfile.write(file_data)
        tfile.seek(0)
        tfile.flush()
        yield tfile.name
        tfile.close()
