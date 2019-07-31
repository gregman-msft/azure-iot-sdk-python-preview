# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import threading


class EventedCallback(object):
    """
    A sync callback whose completion can be waited upon.
    """

    def __init__(self, callback):
        """
        Creates an instance of an EventedCallback from a callback function.

        :param callback: Callback function that can be waited on
        """
        self.completion_event = threading.Event()
        self.exception = None
        self.result = None

        def wrapping_callback(*args, **kwargs):
            try:
                result = callback(*args, **kwargs)
            except Exception as e:
                self.exception = e
            else:
                self.result = result

            self.completion_event.set()

        self.callback = wrapping_callback

    def __call__(self, *args, **kwargs):
        """
        Calls the callback.
        """
        self.callback(*args, **kwargs)

    def wait(self, *args, **kwargs):
        """
        Wait for the callback to be called, and return the results.
        """
        self.completion_event.wait(*args, **kwargs)

        if self.exception:
            raise self.exception
        else:
            return self.result
