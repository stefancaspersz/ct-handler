import hmac
from os import environ
from flask import Flask,request,json,redirect,url_for,abort,jsonify
from hashlib import sha1

app = Flask(__name__)

@app.route('/app')
def hello():
    # response = jsonify({'ip': request.remote_addr})
    response = jsonify({'True-Client-IP': request.headers['True-Client-IP']})
    print(request.headers['True-Client-IP'])
    print(request.headers['User-Agent'])
    return response

@app.route('/app/webhooks',methods=['GET','POST'])
def webhooks():
    if request.method == 'POST' and request.is_json:
        data = request.json
        # Look for the signature in the request headers
        if "X-Hub-Signature" not in request.headers:
            abort(403)

        signature = request.headers.get("X-Hub-Signature", "").split("=")[1]

        # Generate our own signature based on the request payload
        secret = environ['APP_SECRET'].encode('utf-8')
        mac = hmac.new(secret, msg=request.data, digestmod=sha1)
        # Ensure the two signatures match
        if not str(mac.hexdigest()) == str(signature):
            abort(403)

        print(data['object'])
        for entry in data['entry']:
            print("id:{} time:{}".format(entry['id'],entry['time']))
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

