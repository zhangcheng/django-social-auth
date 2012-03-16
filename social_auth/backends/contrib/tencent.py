"""
Tencent weibo OAuth support.

This contribution adds support for TENCENT weibo OAuth service. The settings
TENCENT_CONSUMER_KEY and TENCENT_CONSUMER_SECRET must be defined with the values
given by Tencent application registration process.
"""
from oauth2 import SignatureMethod_HMAC_SHA1, Request as OAuthRequest
from django.utils import simplejson
from social_auth.backends import OAuthBackend, ConsumerBasedOAuth, USERNAME


TENCENT_SERVER = "http://open.t.qq.com/api"
TENCENT_REQUEST_TOKEN_URL = "https://open.t.qq.com/cgi-bin/request_token"
TENCENT_ACCESS_TOKEN_URL = "https://open.t.qq.com/cgi-bin/access_token"
TENCENT_AUTHORIZE_URL = "https://open.t.qq.com/cgi-bin/authorize"
TENCENT_CHECK_AUTH = "%s/user/info?format=json" % TENCENT_SERVER


class TencentBackend(OAuthBackend):
    name = "tencent"

    def get_user_id(self, details, response):
        return response["data"]["name"]

    def get_user_details(self, response):
        return {
            USERNAME: response["data"]["nick"],
        }


class TencentAuth(ConsumerBasedOAuth):
    AUTH_BACKEND = TencentBackend
    AUTHORIZATION_URL = TENCENT_AUTHORIZE_URL
    REQUEST_TOKEN_URL = TENCENT_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = TENCENT_ACCESS_TOKEN_URL
    SERVER_URL = TENCENT_SERVER
    SETTINGS_KEY_NAME = "TENCENT_CONSUMER_KEY"
    SETTINGS_SECRET_NAME = "TENCENT_CONSUMER_SECRET"

    def oauth_request(self, token, url, extra_params=None):
        """Generate OAuth request, setups callback url"""
        params = {'oauth_callback': self.redirect_uri}
        if extra_params:
            params.update(extra_params)

        if 'oauth_verifier' in self.data:
            params['oauth_verifier'] = self.data['oauth_verifier']
            # If including callback url in request for access token
            # would receive 401 Invalid signature
            del params['oauth_callback']

        request = OAuthRequest.from_consumer_and_token(self.consumer,
            token=token,
            http_url=url,
            parameters=params,
            is_form_encoded=True
        )
        request.sign_request(SignatureMethod_HMAC_SHA1(), self.consumer, token)
        return request

    def user_data(self, access_token):
        request = self.oauth_request(access_token, TENCENT_CHECK_AUTH)
        try:
            return simplejson.loads(self.fetch_response(request))
        except:
            return None

    @classmethod
    def enabled(cls):
        return True


# Backend definition
BACKENDS = {
    'tencent': TencentAuth,
}
