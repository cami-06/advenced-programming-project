import logging
from pathlib import Path


# =============================
# LOG FILE SETUP
# =============================

LOG_DIR = Path("data/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "scanner.log"


# =============================
# LOGGER CONFIGURATION
# =============================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()  # console output
    ]
)


# =============================
# GLOBAL LOGGER INSTANCE
# =============================

logger = logging.getLogger("PentestFramework")
