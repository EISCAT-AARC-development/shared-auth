#!/usr/bin/env python3
import jwt
from furl import furl, Path 
from datetime import datetime, timedelta
from hashlib import sha256
import os

class UrlValidationException(Exception): pass

class TokenUsageLimitExceededException(Exception): pass

class ExtendedUrl(furl):

    logpath = 'download.log'

    def __init__(self, url):
        super(ExtendedUrl, self).__init__(url)
        self.decoded_jwt = None
        self.exc_in_validation = None

    def _get_url_part_to_validate(self, path, query):
        res_url = str(path) + '/' + query.encode()
        if (res_url[0] == '/'):
            res_url = res_url[1:]
        return res_url

    def _create_token(self, user_id, exp_seconds, download_times, private_key):
        jwt_payload = {
            'sub' : str(sha256(user_id.encode('utf-8'))),
            'exp' : datetime.utcnow() + timedelta(seconds=exp_seconds),
            'r_url' : self._get_url_part_to_validate(self.path, self.query),
            'd_times' : download_times
        }

        encoded_jwt = jwt.encode(jwt_payload, private_key, algorithm='RS256')
        return encoded_jwt

    def _validate_token_usage_limit(self, encoded_jwt, limit):

        if not(os.path.exists(self.logpath)):
            with open(self.logpath, 'w+') as file:
                file.write('{token}\n'.format(token=encoded_jwt))

        else:
            if (len(filter(lambda line: line == encoded_jwt, open(self.logpath, 'r').read().splitlines())) >= limit):
                raise TokenUsageLimitExceededException('token usage exceeded the limit defined')
            else:
                with open(self.logpath, 'a') as log:
                    log.write('{token}\n'.format(token=encoded_jwt))


    def _extract_token(self, public_key):
        encoded_jwt = self.path.segments[0] 
        # pyjwt automatically validate signature and expiration time
        token = jwt.decode(encoded_jwt, public_key)
        path_without_token = Path(self.path.segments[1:])
        path_without_token.isabsolute = False
        url_part_to_validate = self._get_url_part_to_validate(path_without_token, self.query)
        if (token['r_url'] != url_part_to_validate):
            raise UrlValidationException('resource url validation error') 

        self._validate_token_usage_limit(encoded_jwt, token['d_times'])    

        self.decoded_jwt = token

    def _extraction_not_already_performed(self):
        return self.decoded_jwt is None and self.exc_in_validation is None

    def _validate(self, public_key):
        if (self._extraction_not_already_performed()):
            try:
                self._extract_token(public_key)
            except Exception as e:
                self.exc_in_validation = e
                raise e
        else:
            if (self.exc_in_validation is not None):
                raise self.exc_in_validation
            else:
                return self.decoded_jwt


    def inject_token(self, user_id, exp_seconds, download_times, private_key):
        encoded_jwt = self._create_token(user_id, exp_seconds, download_times, private_key)
        path_within_token = [encoded_jwt] + self.path.segments 
        self.set(path=path_within_token)

    def is_valid(self, public_key):
        try: 
            self._validate(public_key)
        except:
            return False
        return self.exc_in_validation is None  

    def get_claims(self, public_key):
        """
        Raises
        ------
        UrlValidationException
            The resource url within the token does not match the one to which the token is prepended  

        ExpiredSignatureError
            The token is expired

        TokenUsageLimitExceededException
            The token was used more than the number of times it was allowed to

        DecodeError
            Error in decoding token

        ImmatureSignatureError
            The signature is invalid

        """
        return self._validate(public_key)

    def remove_token_from_url(self):
        self.set(path=self.path.segments[1:])
