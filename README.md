# ct-handler
A flask app to handle CT webhooks from Facebook

# Set ENV vars
```console
$ export SERVER_TOKEN=<secret token used to validate initial webhook subscription>
$ export APP_SECRET=<secret token used to validate webhook requests>
$ export FLASK_APP=server.py
$ export FLASK_ENV=development
$ flask run
```
