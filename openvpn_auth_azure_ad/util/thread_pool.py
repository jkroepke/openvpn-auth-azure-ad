# from: https://stackoverflow.com/a/24457608/8087167

import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class ThreadPoolExecutorStackTraced(ThreadPoolExecutor):
    def submit(self, fn, *args, **kwargs):
        """Submits the wrapped function instead of `fn`"""

        return super(ThreadPoolExecutorStackTraced, self).submit(
            self._function_wrapper, fn, *args, **kwargs
        )

    @staticmethod
    def _function_wrapper(fn, *args, **kwargs):
        """Wraps `fn` in order to preserve the traceback of any kind of
        raised exception
        """
        # noinspection PyBroadException
        try:
            return fn(*args, **kwargs)
        except Exception:
            logger.exception("Exception in thread")
