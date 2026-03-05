import os

# Domain that we attempt to DNS lookup
TEST_DOMAIN = "example.com"

# Name of the environment variable we set to signal that the test is running
# inside of shadow.
RUNNING_IN_SHADOW_ENV = "RUNNING_IN_SHADOW"


def running_in_shadow() -> bool:
    return bool(os.environ.get(RUNNING_IN_SHADOW_ENV))
