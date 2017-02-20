import os


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'debug': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
        'elasticsearch': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'elk.BulkUdp',
            'host': os.getenv('ELK_SERVER'),
            'port': int(os.getenv('ELK_PORT')),
            'service': os.getenv('ELK_SERVICE'),
        },
    },
    'loggers': {
        '': {
            'handlers': ['debug'],
            'level': 'DEBUG',
            'propagate': True
        },
    }
}
