import base64
import re
import json
import logging
import os
import sys
import uuid
import urllib.parse

import flask
from flask import Flask, request, jsonify
from flask_mobility import Mobility
from flask_restful import Resource, Api
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix

import arrow
import requests
import redis
import jsonschema

ENV_VAR_NAME_REDIS_URL = None
ENV_VAR_NAME_LOGLEVEL = "LOGLEVEL"

app = Flask(__name__)
app.logger.setLevel(os.getenv(ENV_VAR_NAME_LOGLEVEL, logging.INFO))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

Mobility(app)
api = Api(app)



class CacheIfCacheCan:
    """
    A wrapper around getting/setting to a redis back end, if configured. A convenience class so code doesn't have to
    repeat boilerplate logic to check if redis has been configured or not. If redis isn't configured getting will
    always return None and setting will just be ignored
    """
    _redis_interface = None

    def __init__(self, redis_interface):
        self._redis_interface = redis_interface

    def get(self, key, is_json=False):
        if self._redis_interface is None:
            return None
        else:
            value = self._redis_interface.get(key)
            if value is None:
                return None
            elif is_json:
                value = json.loads(value)

            return value

    def set(self, key, value, timeout=None, is_json=False):
        if self._redis_interface is None:
            pass
        else:
            if is_json:
                value = json.dumps(value)

            if timeout is None:
                self._redis_interface.set(key, value)
            else:
                self._redis_interface.set(key, value, timeout)


# If redis is configured set up "cache" to use it
if ENV_VAR_NAME_REDIS_URL is not None and os.getenv(ENV_VAR_NAME_REDIS_URL, None) is not None:
    redis_url = urllib.parse.urlparse(os.environ.get(ENV_VAR_NAME_REDIS_URL))
    app.logger.info(f"Setting up to use redis cache at {redis_url.hostname}")
    r = redis.Redis(host=str(redis_url.hostname),
                    port=redis_url.port,
                    password=redis_url.password)
    cache = CacheIfCacheCan(r)
else:
    app.logger.info(f"Environment variable '{ENV_VAR_NAME_REDIS_URL}' not set so not using redis caching")
    cache = CacheIfCacheCan(None)


def log_requests_response(formated_msg_string, flask_response: flask.Response, level=logging.INFO, logger=app.logger):
    try:
        log_id = str(uuid.uuid4())

        response_as_string = f"{str(flask_response.url)}\n\n{flask_response.status_code}\n\n{flask_response.headers}\n\n{str(flask_response.text)[:1024]}"
        b64_encoded_response_string = str(base64.b64encode(response_as_string.encode('utf-8')))
        app.logger.log(level, formated_msg_string % {"log_id": log_id, "serialized_response": b64_encoded_response_string})

        return log_id

    except Exception as e:
        app.logger.critical(f"log_requests_response failed to log message due to exception '{e}'")
        app.logger.exception(e)
        return None


@app.route('/css/<path:path>')
def send_css(path):
    return flask.send_from_directory('staticfiles/css', path)


@app.route('/js/<path:path>')
def send_js(path):
    return flask.send_from_directory('staticfiles/js', path)


@app.route('/fonts/<path:path>')
def send_font(path):
    return flask.send_from_directory('staticfiles/fonts', path)


@app.route('/media/<path:path>')
def send_media(path):
    return flask.send_from_directory('staticfiles/media', path)


@app.route('/favicon.ico')
def send_icon():
    return [None, 404]


@app.route("/")
@app.route("/index.html")
@app.route("/index.htm")
def default_page():
    return flask.render_template("index.jinja2")

# RESTful API
class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}

api.add_resource(HelloWorld, '/api/')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
