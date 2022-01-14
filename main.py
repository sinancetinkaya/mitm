# mitmdump -p 8081 -s main.py
# "C:\Users\sinan\AppData\Local\Chromium\Application\chrome.exe" --proxy-server="localhost:8081"

import inspect
import json
import os
import urllib.parse
from mitmproxy.http import HTTPFlow
from mitmproxy.tools import main
from mitmproxy.tools.dump import DumpMaster
import logging
import operator


log_format = '%(levelname).1s,%(asctime)s,%(name)s,%(lineno)d: %(message)s'
logging.basicConfig(level=logging.DEBUG, format=log_format)
log_formatter = logging.Formatter(log_format)

log_handler = logging.FileHandler("log.txt", mode='w')
log_handler.setFormatter(log_formatter)
logging.getLogger().addHandler(log_handler)

logging.getLogger("hpack.hpack").setLevel(logging.WARNING)
logging.getLogger("hpack.table").setLevel(logging.WARNING)
logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(logging.WARNING)

log = logging.getLogger(__name__)

CONNECTION_LOGS = {}
DOMAINS = ["api.plugshare.com"]
FOLDER = os.path.join(".\\", DOMAINS[0])


class AddHeader:
    def __init__(self):
        self.content_types = ['json', 'html']
        self.LOG_COUNTER = 0

    def response(self, flow):
        if any(map(lambda domain: domain in flow.request.host, DOMAINS)):
            if 'content-type' in flow.response.headers:
                for content_type in self.content_types:
                    if content_type in flow.response.headers['content-type']:
                        self.log_response(flow)
            else:
                self.log_response(flow)

    def websocket_handshake(self, flow):
        self.log_response(flow)

    def websocket_start(self, flow):
        self.log_response(flow)

    def websocket_message(self, flow):
        self.log_response(flow)

    def log_response(self, flow: HTTPFlow):
        self.LOG_COUNTER += 1

        if isinstance(flow, HTTPFlow):
            LOG_ENTRY = f"{self.LOG_COUNTER}-{flow.request.method}"
            CONNECTION_LOG = {"url": flow.request.url}
            methods = [
                'request.headers',
                'request.cookies',
                'request.content',
                'response.headers',
                'response.cookies',
                'response.content',
            ]
        elif flow.websocket:
            fname = inspect.stack()[1].function
            LOG_ENTRY = f"{self.LOG_COUNTER}-{fname.upper()}"
            CONNECTION_LOG = {"url": flow.handshake_flow.request.url}
            methods = [
                'messages',
                'request.headers',
                'request.cookies',
                'handshake_flow.request.headers',
                'handshake_flow.request.cookies',
            ]
        else:
            log.warning(f"unknown flow type: {type(flow)}")
            return False

        for method in methods:
            try:
                attribute = operator.attrgetter(method)(flow)
                if attribute is None:
                    continue
            except AttributeError:
                continue

            if method.endswith('headers') or method.endswith('cookies'):
                output = dict(attribute)

            elif method.endswith('content'):
                content = attribute.decode('utf-8')

                if "<html" in content and "<body" in content:
                    output_file = os.path.join(FOLDER, f"{LOG_ENTRY}.html")
                    with open(output_file, mode='w', encoding='utf-8') as fp:
                        fp.write(content)
                    return output_file  # HTML content is not useful, trim it
                else:
                    content = urllib.parse.unquote(content)
                    output = self.jsonify_content(content)

            elif method.endswith('messages'):
                output = []

                if len(attribute):
                    message = attribute[-1]

                    if message.from_client:
                        method = "message-SENT"
                    else:
                        method = "message-RECV"

                    try:
                        data = message.content.split('~', -1)[4]
                    except IndexError:
                        data = message.content

                    try:
                        output = self.jsonify_content(data)
                    except json.JSONDecodeError:
                        output = data

            else:
                output = str(attribute)

            CONNECTION_LOG[method] = output

        CONNECTION_LOGS[LOG_ENTRY] = CONNECTION_LOG

    def jsonify_content(self, content):

        try:
            return json.loads(content)
        except:
            pass

        try:
            return dict([element.split('=') for element in content.split('&')])
        except:
            pass

        return content


if __name__ == "__main__":

    if not os.path.exists(FOLDER):
        os.makedirs(FOLDER)

    options = main.options.Options(listen_host='127.0.0.1', listen_port=8081)
    master = DumpMaster(options=options)

    # print(m.addons)
    master.addons.add(AddHeader())
    print(master.addons)


    # m.addons.add(core.Core())

    def get_json(obj):
        return json.dumps(obj, indent=4, default=lambda o: getattr(o, '__dict__', str(o)))


    try:
        master.run()
    except KeyboardInterrupt:
        master.shutdown()
    finally:
        output_file = os.path.join(FOLDER, "CONNECTION_DUMP.json")
        with open(output_file, mode="w") as fp:
            fp.write(get_json(CONNECTION_LOGS))
