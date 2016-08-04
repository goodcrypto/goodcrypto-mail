'''
    Crypto RQ worker settings.

    Copyright 2014 GoodCrypto
    Last modified: 2015-09-21

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

#from goodcrypto.utils.constants import REDIS_HOST

REDIS_PORT = 6384
#REDIS_URL = 'http://{}:{}'.format(REDIS_HOST, REDIS_PORT)
CRYPTO_REDIS_PORT = REDIS_PORT

# Probably don't need a password since the port should be blocked plus
# see the warnings in /etc/redis about the downsides of using a password
# REDIS_PASSWORD = 'very secret'

# You can also specify the Redis DB to use
# REDIS_DB = 3

# Queues to listen on
CRYPTO_RQ = 'crypto'
QUEUES = [CRYPTO_RQ]

# If you're using Sentry to collect your runtime exceptions, you can use this
# to configure RQ for it in a single step
#SENTRY_DSN = 'http://public:secret@example.com/1'

KEY_SUFFIX = 'key'
FINGERPRINT_SUFFIX = 'fingerprint'

