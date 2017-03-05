#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""FileReadBackwards module."""

import io
from .buffer_work_space import BufferWorkSpace

supported_encodings = ["utf-8", "ascii", "latin-1"]  # any encodings that are backward compatible with ascii should work


class FileReadBackwards:

    """Class definition for FileReadBackwards."""

    def __init__(self, path, encoding="utf-8", chunk_size=io.DEFAULT_BUFFER_SIZE):
        """Constructor for FileReadBackwards.

        Args:
            path: Path to the file to be read
            encoding (str): Encoding
            chunk_size (int): How many bytes to read at a time
        """
        if encoding not in supported_encodings:
            error_message = "{} encoding was not supported/tested.".format(encoding)
            error_message += "Supported encodings are '{}'".format(",".join(supported_encodings))
            raise NotImplementedError(error_message)

        self.path = path
        self.encoding = encoding
        self.chunk_size = chunk_size

    def __iter__(self):
        """Yield unicode string from the last line until the beginning of file."""
        # Using binary mode, because some encodings such as "utf-8" use variable number of
        # bytes to encode different Unicode points.
        # Without using binary mode, we would probably need to understand each encoding more
        # and do the seek operations to find the proper boundary before issuing read
        with io.open(self.path, mode="rb") as fp:

            b = BufferWorkSpace(fp, self.chunk_size)
            while True:
                if b.has_returned_every_line():
                    break
                b.read_until_yieldable()
                r = b.return_line()
                yield r.decode(self.encoding)
