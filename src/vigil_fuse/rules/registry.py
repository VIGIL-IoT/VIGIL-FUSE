from .base import RuleDefinition
from .credentials import RULE as CREDENTIALS
from .esp_idf_boot_validation import RULE as ESP_IDF_BOOT_VALIDATION
from .esp_idf_deep_sleep_validation import RULE as ESP_IDF_DEEP_SLEEP_VALIDATION
from .plaintext_http import RULE as PLAINTEXT_HTTP
from .plaintext_mqtt import RULE as PLAINTEXT_MQTT
from .private_key import RULE as PRIVATE_KEY
from .tls import RULE as TLS

RULES: tuple[RuleDefinition, ...] = (
    CREDENTIALS,
    PRIVATE_KEY,
    TLS,
    PLAINTEXT_HTTP,
    PLAINTEXT_MQTT,
    ESP_IDF_BOOT_VALIDATION,
    ESP_IDF_DEEP_SLEEP_VALIDATION,
)
