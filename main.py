"""
mitmdump -p 8081 -s main.py
"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --proxy-server="localhost:8081"

"""
import json
import urllib.parse
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
import logging


# import ptvsd

# # Allow other computers to attach to ptvsd at this IP address and port.
# ptvsd.enable_attach(address=('localhost', 5678), redirect_output=True)

# # Pause the program until a remote debugger is attached
# print("WAITING FOR DEBUG ATTACH")
# ptvsd.wait_for_attach()

# log_format = '%(levelname).1s,%(asctime)s,%(name)s,%(lineno)d: %(message)s'
log_format = '%(message)s'
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


class AddHeader:
    def __init__(self):
        self.domain = "freelancer"
        self.content_types = ['json', 'html']
        self.LOG_COUNTER = 0

    def response(self, flow):
        if self.domain in flow.request.host:
            if 'content-type' in flow.response.headers:
                for content_type in self.content_types:
                    if content_type in flow.response.headers['content-type']:
                        self.log_response(flow)
            else:
                self.log_response(flow)

    def log_response(self, flow):
        self.LOG_COUNTER += 1

        CONNECTION_LOG = {
            "url": flow.request.url
        }
        CONNECTION_LOGS[f"{self.LOG_COUNTER}-{flow.request.method}"] = CONNECTION_LOG

        for method in ['request', 'response']:
            obj = getattr(flow, method)

            CONNECTION_LOG[method] = {}

            for key in ['headers', 'cookies', 'content']:

                if not hasattr(obj, key):
                    continue

                attribute = getattr(obj, key)
                if attribute is None:
                    continue

                if key in ['headers', 'cookies']:
                    output = dict(attribute)

                elif key == 'content':
                    output = self.jsonify_content(attribute)

                else:
                    output = str(attribute)

                CONNECTION_LOG[method][key] = output

    def jsonify_content(self, attribute):
        content = attribute.decode('utf-8')
        content = urllib.parse.unquote(content)

        try:
            return json.loads(content)
        except:
            pass

        try:
            return dict([element.split('=') for element in content.split('&')])
        except:
            pass

        if content.startswith('<'):
            return content[:80]  # HTML content is not useful, trim it

        return content


if __name__ == "__main__":

    opts = options.Options(listen_host='127.0.0.1', listen_port=8081)
    opts.add_option("body_size_limit", int, 0, "")
    opts.add_option("keep_host_header", bool, True, "")    

    pconf = proxy.config.ProxyConfig(opts)

    m = DumpMaster(None)
    m.server = proxy.server.ProxyServer(pconf)
    # print(m.addons)
    m.addons.add(AddHeader())
    print(m.addons)
    # m.addons.add(core.Core())

    def get_json(obj):
        return json.dumps(obj, indent=4, default=lambda o: getattr(o, '__dict__', str(o)))

    try:
        m.run()
    except KeyboardInterrupt:
        m.shutdown()
        with open("CONNECTION_LOGS.json", mode="w") as fp:
            fp.write(get_json(CONNECTION_LOGS))
