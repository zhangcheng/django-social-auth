import hashlib
import datetime
from urllib import urlencode
from urllib2 import urlopen

from django.utils import simplejson

from social_auth.backends import BaseOAuth2, OAuthBackend, USERNAME
from social_auth.utils import setting


TAOBAO_SERVER = 'http://gw.api.taobao.com/router/rest'
TAOBAO_AUTHORIZATION_URL = 'https://oauth.taobao.com/authorize'
TAOBAO_ACCESS_TOKEN_URL = 'https://oauth.taobao.com/token'


class TaobaoBackend(OAuthBackend):
    name = 'taobao'

    def get_user_id(self, details, response):
        print response
        return response['user_get_response']['user']['user_id']

    def get_user_details(self, response):
        """Return user details from Instagram account"""
        return {
            USERNAME: response['user_get_response']['user']["nick"],
        }


class TaobaoAuth(BaseOAuth2):
    AUTHORIZATION_URL = TAOBAO_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = TAOBAO_ACCESS_TOKEN_URL
    SERVER_URL = TAOBAO_SERVER
    AUTH_BACKEND = TaobaoBackend
    SETTINGS_KEY_NAME = 'TAOBAO_CLIENT_ID'
    SETTINGS_SECRET_NAME = 'TAOBAO_CLIENT_SECRET'

    def _signature(self, params):
        """ See here: http://open.taobao.com/doc/detail.htm?id=111#s6 """
        parts = ["%s%s" % (n, params[n]) for n in sorted(params.keys())]
        parts.insert(0, setting(self.SETTINGS_SECRET_NAME))
        parts.append(setting(self.SETTINGS_SECRET_NAME))
        body = "".join(parts)

        if isinstance(body, unicode): body = body.encode("utf-8")
        return hashlib.md5(body).hexdigest().upper()

    def _request(self, method, access_token, **params):
        params["method"] = method
        params["session"] = access_token
        params["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        params["format"] = "json"
        params["app_key"] = setting(self.SETTINGS_KEY_NAME)
        params["v"] = "2.0"
        params["sign_method"] = "md5"
        params["sign"] = self._signature(params)

        url = TAOBAO_SERVER + '?' + urlencode(params)

        try:
            return simplejson.load(urlopen(url))
        except ValueError:
            return None

    def user_data(self, access_token):
        """Loads user data from service"""
        params = {"fields": "user_id,nick,location,type"}
        return self._request("taobao.user.get", access_token, **params)

# Backend definition
BACKENDS = {
    'taobao': TaobaoAuth,
}
