import hmac
from os import environ
from flask import Flask,request,redirect,url_for,abort,jsonify
from hashlib import sha1

app = Flask(__name__)

@app.route('/app',methods=['GET'])
def hello():
    try:
        # this only works when a reverse proxy like nginx provides the headers
        response = jsonify({'True-Client-IP': request.headers['True-Client-IP'],'X-Forwarded-For': request.headers['X-Forwarded-For']})
    except:
        # looks like we have not recieved the correct headers
        response = jsonify({'ip': request.remote_addr})
    print(request.headers)
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
    app.run()
