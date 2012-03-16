"""
Douban OAuth support.

This contribution adds support for Douban OAuth service. The settings
DOUBAN_CONSUMER_KEY and DOUBAN_CONSUMER_SECRET must be defined with the values
given by Douban application registration process.

By default account id and token expiration time are stored in extra_data
field, check OAuthBackend class for details on how to extend it.
"""


import urllib
from social_auth.backends import OAuthBackend, ConsumerBasedOAuth, USERNAME
from django.utils import simplejson


DOUBAN_SERVER = "http://api.douban.com"
DOUBAN_REQUEST_TOKEN_URL = "http://www.douban.com/service/auth/request_token"
DOUBAN_ACCESS_TOKEN_URL = "http://www.douban.com/service/auth/access_token"
DOUBAN_AUTHORIZE_URL = "http://www.douban.com/service/auth/authorize"
DOUBAN_CHECK_AUTH = "%s/%s?alt=json" % (DOUBAN_SERVER, urllib.quote("people/@me"))


class DoubanBackend(OAuthBackend):
    name = "douban"

    def get_user_id(self, details, response):
        return response["db:uid"]["$t"]

    def get_user_details(self, response):
        return {
            USERNAME: response["title"]["$t"],
        }


class DoubanAuth(ConsumerBasedOAuth):
    AUTH_BACKEND = DoubanBackend
    AUTHORIZATION_URL = DOUBAN_AUTHORIZE_URL
    REQUEST_TOKEN_URL = DOUBAN_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = DOUBAN_ACCESS_TOKEN_URL
    SERVER_URL = DOUBAN_SERVER
    SETTINGS_KEY_NAME = "DOUBAN_CONSUMER_KEY"
    SETTINGS_SECRET_NAME = "DOUBAN_CONSUMER_SECRET"

    def user_data(self, access_token):
        request = self.oauth_request(access_token, DOUBAN_CHECK_AUTH)
        try:
            return simplejson.loads(self.fetch_response(request))
        except:
            return None

    @classmethod
    def enabled(cls):
        return True


# Backend definition
BACKENDS = {
    'douban': DoubanAuth,
}
