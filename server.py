from os import environ
from flask import Flask,request,json,redirect,url_for

app = Flask(__name__)

@app.route('/app')
def hello():
    return '<head><title>Webhooks with Python</title></head><body><h1>Webhooks with Python</h1></body>'

@app.route('/app/webhooks',methods=['GET','POST'])
def webhooks():
    if request.method == 'POST' and request.is_json:
        data = request.json
        print(data['object'])
        for entry in data['entry']:
            print("{} {}".format(entry['id'],entry['time']))
            for change in entry['changes']:
                if change['field'] == "certificate":
                    print('NEW CERT ISSUED')
                    print(change['value']['cert_hash_sha256'])
                elif change['field'] == "phishing":
                    print('POTENTIAL PHISHING DETECTED')
                    print(change['value']['ct_cert']['cert_hash_sha256'])
                    print(change['value']['phished_domain'])
                    print(change['value']['phishing_domains'])
        return "JSON received!", 200
    else:
        args = request.args
        mode = args.get("hub.mode", default="", type=str)
        challenge = args.get("hub.challenge", default=0, type=int)
        verify_token = args.get("hub.verify_token", default="", type=str)
        if verify_token == environ['SERVER_TOKEN']:
            return str(challenge)
        else:
            return redirect(url_for('hello'))

if __name__ == '__main__':
    app.debug=True
    app.run()

