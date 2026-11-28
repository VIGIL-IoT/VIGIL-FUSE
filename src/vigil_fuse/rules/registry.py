from .base import RuleDefinition
from .credentials import RULE as CREDENTIALS
from .esp_idf_boot_validation import RULE as ESP_IDF_BOOT_VALIDATION
from .esp_idf_deep_sleep_validation import RULE as ESP_IDF_DEEP_SLEEP_VALIDATION
from .plaintext_http import RULE as PLAINTEXT_HTTP
from .plaintext_mqtt import RULE as PLAINTEXT_MQTT
from .private_key import RULE as PRIVATE_KEY
from .tls import RULE as TLS
from .software_process import RULE as SOFTWARE_PROCESS
from .software_container import RULE as SOFTWARE_CONTAINER
from .software_yaml import RULE as SOFTWARE_YAML
from .software_dynamic_eval import RULE as SOFTWARE_DYNAMIC_EVAL

RULES: tuple[RuleDefinition, ...] = (
    CREDENTIALS,
    PRIVATE_KEY,
    TLS,
    PLAINTEXT_HTTP,
    PLAINTEXT_MQTT,
    ESP_IDF_BOOT_VALIDATION,
    ESP_IDF_DEEP_SLEEP_VALIDATION,
    SOFTWARE_PROCESS,
    SOFTWARE_CONTAINER,
    SOFTWARE_YAML,
    SOFTWARE_DYNAMIC_EVAL,
)
