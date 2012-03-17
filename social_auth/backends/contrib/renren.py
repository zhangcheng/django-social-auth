from urllib import urlencode
from urllib2 import urlopen, HTTPError

from django.contrib.auth import authenticate
from django.utils import simplejson

from social_auth.backends import BaseOAuth2, OAuthBackend, USERNAME
from social_auth.utils import setting
from social_auth.backends.exceptions import AuthException, AuthCanceled, AuthFailed


RENREN_SERVER = 'http://api.renren.com/restserver.do'
RENREN_AUTHORIZATION_URL = 'https://graph.renren.com/oauth/authorize'
RENREN_ACCESS_TOKEN_URL = 'https://graph.renren.com/oauth/token'
RENREN_CHECK_AUTH = '%s?Users.getInfo' % RENREN_SERVER


class RenrenBackend(OAuthBackend):
    name = 'renren'

    def get_user_id(self, details, response):
        return response['user']['id']

    def get_user_details(self, response):
        """Return user details from Instagram account"""
        return {
            USERNAME: response["user"]["name"],
        }


class RenrenAuth(BaseOAuth2):
    AUTHORIZATION_URL = RENREN_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = RENREN_ACCESS_TOKEN_URL
    SERVER_URL = RENREN_SERVER
    AUTH_BACKEND = RenrenBackend
    SETTINGS_KEY_NAME = 'RENREN_CLIENT_ID'
    SETTINGS_SECRET_NAME = 'RENREN_CLIENT_SECRET'

    def user_data(self, response):
        """Loads user data from service"""
        return response

    def auth_complete(self, *args, **kwargs):
        if 'code' not in self.data:
            if self.data.get('error') == 'access_denied':
                raise AuthCanceled(self)
            else:
                raise AuthException(self)

        post_data = urlencode({
            'client_id': setting(self.SETTINGS_KEY_NAME),
            'redirect_uri': self.redirect_uri,
            'client_secret': setting(self.SETTINGS_SECRET_NAME),
            'code': self.data['code'],
            'grant_type': 'authorization_code'
        })
        try:
            response = simplejson.loads(urlopen(self.ACCESS_TOKEN_URL, post_data).read())
        except HTTPError:
            raise AuthFailed(self, 'There was an error authenticating the app')

        access_token = response['access_token']
        data = self.user_data(response)

        if data is not None:
            data['access_token'] = access_token
            # expires will not be part of response if offline access
            # premission was requested
            if 'expires_in' in response:
                data['expires_in'] = response['expires_in']

        kwargs.update({'auth': self,
                       'response': data,
                       self.AUTH_BACKEND.name: True})
        return authenticate(*args, **kwargs)

# Backend definition
BACKENDS = {
    'renren': RenrenAuth,
}
