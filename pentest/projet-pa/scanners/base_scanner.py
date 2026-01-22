from abc import ABC, abstractmethod
from core.logger import logger


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.

    Enforces a common interface and lifecycle.
    """

    def __init__(self, crawler, http_client, reporter):
        self.crawler = crawler
        self.http = http_client
        self.reporter = reporter

    @abstractmethod
    def scan(self):
        """
        Entry point for scanner execution.
        Must be implemented by all scanners.
        """
        pass

    # =============================
    # OPTIONAL HOOKS
    # =============================

    def pre_scan(self):
        """
        Hook executed before scan starts.
        """
        logger.info(f"Starting {self.__class__.__name__}")

    def post_scan(self):
        """
        Hook executed after scan ends.
        """
        logger.info(f"Finished {self.__class__.__name__}")
