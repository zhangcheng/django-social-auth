"""
Weibo OAuth support.

This contribution adds support for Weibo OAuth service. The settings
DOUBAN_CONSUMER_KEY and DOUBAN_CONSUMER_SECRET must be defined with the values
given by Douban application registration process.

By default account id and token expiration time are stored in extra_data
field, check OAuthBackend class for details on how to extend it.
"""


from social_auth.backends import OAuthBackend, ConsumerBasedOAuth, USERNAME
from django.utils import simplejson


WEIBO_SERVER = "http://api.t.sina.com.cn"
WEIBO_REQUEST_TOKEN_URL = "http://api.t.sina.com.cn/oauth/request_token"
WEIBO_ACCESS_TOKEN_URL = "http://api.t.sina.com.cn/oauth/access_token"
WEIBO_AUTHORIZE_URL = "http://api.t.sina.com.cn/oauth/authorize"
WEIBO_CHECK_AUTH = "%s/account/verify_credentials.json" % WEIBO_SERVER


class WeiboBackend(OAuthBackend):
    name = "weibo-oauth"

    def get_user_id(self, details, response):
        return response["id"]

    def get_user_details(self, response):
        return {
            USERNAME: response["screen_name"],
        }


class WeiboOAuth(ConsumerBasedOAuth):
    AUTH_BACKEND = WeiboBackend
    AUTHORIZATION_URL = WEIBO_AUTHORIZE_URL
    REQUEST_TOKEN_URL = WEIBO_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = WEIBO_ACCESS_TOKEN_URL
    SERVER_URL = WEIBO_SERVER
    SETTINGS_KEY_NAME = "WEIBO_CONSUMER_KEY"
    SETTINGS_SECRET_NAME = "WEIBO_CONSUMER_SECRET"

    def user_data(self, access_token):
        request = self.oauth_request(access_token, WEIBO_CHECK_AUTH)
        return simplejson.loads(self.fetch_response(request))

    @classmethod
    def enabled(cls):
        return True


# Backend definition
BACKENDS = {
    'weibo-oauth': WeiboOAuth,
}
