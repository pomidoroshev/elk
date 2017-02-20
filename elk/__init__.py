import datetime
import json
import logging
from logging.handlers import DatagramHandler
import socket
import sys
import time
import traceback

SKIP_EXTRA_FIELDS = set(['args', 'asctime', 'created', 'exc_info',  'exc_text',
                         'filename', 'funcName', 'id', 'levelname', 'levelno',
                         'lineno', 'module', 'msecs', 'msecs', 'message',
                         'msg', 'name', 'pathname', 'process', 'processName',
                         'relativeCreated', 'thread', 'threadName'])


def exc_handler(exc_type, value, tb):
    lines = traceback.format_exception(exc_type, value, tb)
    logging.exception('Uncaught exception: %s' % ''.join(lines))


sys.excepthook = exc_handler


class BulkUdp(DatagramHandler):
    """Elasticsearch Bulk Udp handler

    implements the bulk UDP for a message:
    http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/docs-bulk-udp.html

    :param host: The host of the elasticsearch server.
    :param port: The port of the graylog server (default 9700).
    :param max_packet_size: Maximum message size. Fields will be dropped not to
                            exceed this size.
    :param debugging_fields: Send debug fields if true.
    :param extra_fields: Send extra fields on the log record to graylog
                         if true (the default).
    :param fqdn: Use fully qualified domain name of localhost as source
                 host (socket.getfqdn()).
    :param localname: Use specified hostname as source host.
    :param service: Service name
    :param type: The type for log messages
    """

    def __init__(self, host, port=9700, max_packet_size=64*1024,
                 debugging_fields=False, extra_fields=True, fqdn=False,
                 localname=None, service="logstash", type="logs"):
        self.debugging_fields = debugging_fields
        self.extra_fields = extra_fields
        self.max_packet_size = max_packet_size
        self.fqdn = fqdn
        self.localname = localname
        self.service = service
        self.type = type
        DatagramHandler.__init__(self, host, port)

    def emit(self, record):
        """
        Emit a record.

        Pickles the record and writes it to the socket in binary format.
        If there is an error with the socket, silently drop the packet.
        If there was a problem with the socket, re-establishes the
        socket.
        """

        try:
            packet = "{"
            first_field = True

            for key, value in self._generate_fields(record):
                bytes_left = self.max_packet_size - len(packet)
                value_json = json.dumps(value, default=str)

                # There's 5 overhead characters: 2 quotes around the key, the
                # : separator and the kvp separator or terminating bracket.
                if (len(value_json) + len(key) + 5) < bytes_left:
                    if not first_field:
                        packet += ",\"%s\":%s" % (key, value_json)
                    else:
                        packet += "\"%s\":%s" % (key, value_json)
                        first_field = False
                elif bytes_left < 16:
                    break

            packet += "}\n"
            self.send(packet.encode())
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def _generate_fields(self, record):
        yield "@version", "1"

        fields = {}
        if type(record.msg) is dict:
            fields = record.msg
            message = fields.get('message', record.getMessage())
        else:
            message = record.getMessage()

        yield "@fields", fields
        yield "message", message

        if self.fqdn:
            yield "logsource", socket.getfqdn()
        elif self.localname:
            yield "logsource", socket.localname
        else:
            yield "logsource", socket.gethostname()

        yield "severity", record.levelno

        dt = datetime.datetime.utcfromtimestamp(record.created)
        yield '@timestamp', dt.isoformat() + "Z"
        yield 'level', record.levelname
        yield 'name', record.name
        yield 'service', self.service

        if self.debugging_fields:
            yield 'file', record.pathname
            yield 'line', record.lineno
            yield '_function', record.funcName
            yield '_pid', record.process
            yield '_thread_name', record.threadName
            # record.processName was added in Python 2.6.2
            pn = getattr(record, 'processName', None)
            if pn is not None:
                yield '_process_name', pn

        if self.extra_fields:
            for key, value in record.__dict__.items():
                if key not in SKIP_EXTRA_FIELDS and not key.startswith('_'):
                    yield '_%s' % key, value
