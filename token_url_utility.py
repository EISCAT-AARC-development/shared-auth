import jwt
from furl import furl, Path 
from datetime import datetime, timedelta
from hashlib import sha256

class UrlValidationException(Exception): pass

class TokenUsageLimitExceededException(Exception): pass

class ExtendedUrl(furl):

    def __init__(self, url):
        super(ExtendedUrl, self).__init__(url)
        self.decoded_jwt = None
        self.exc_in_validation = None

    # def __get_url_part_to_validate__(self, path, query):
    #     res_url = str(path) + '/' + query.encode()
    #     if (res_url[0] == '/'):
    #         res_url = res_url[1:]
    #     return res_url

    def __create_token__(self, user_id, exp_seconds, download_times, private_key):
        jwt_payload = {
            'sub' : str(sha256(user_id)),
            'exp' : datetime.utcnow() + timedelta(seconds=exp_seconds),
            'path' : str(self.path),
            'query': str(self.query),
            'd_times' : download_times
        }

        encoded_jwt = jwt.encode(jwt_payload, private_key, algorithm='RS256')
        return encoded_jwt

    def __extract_token__(self, public_key, additional_validator=None):
        encoded_jwt = self.path.segments[0] 
        # pyjwt automatically validate signature and expiration time
        token = jwt.decode(encoded_jwt, public_key)
        if (additional_validator is not None):
            additional_validator.validate(token)             
        self.decoded_jwt = token

    def __extraction_not_already_performed__(self):
        return self.decoded_jwt is None and self.exc_in_validation is None

    def __validate__(self, public_key, additional_validator=None):
        if (self.__extraction_not_already_performed__()):
            try:
                self.__extract_token__(public_key, additional_validator)
            except Exception as e:
                self.exc_in_validation = e
                raise e
        else:
            if (self.exc_in_validation is not None):
                raise self.exc_in_validation
        return self.decoded_jwt


    def inject_token(self, user_id, exp_seconds, download_times, private_key):
        encoded_jwt = self.__create_token__(user_id, exp_seconds, download_times, private_key)
        self.set(path=[encoded_jwt], query=None)

    def is_valid(self, public_key):
        try: 
            self.__validate__(public_key)
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
        claims = self.__validate__(public_key)
        return claims
        
    def restore_original_url(self):
        if (self.decoded_jwt is None):
            raise Exception('You must call either is_valid(..) or get_claims(..) method before calling restore_original_url')
        path = self.decoded_jwt['path'] 
        query = self.decoded_jwt['query']
        self.set(path=path, query=query)


class DownloadTimesValidator:

    def validate(self,token):
        max_download_times = token['d_times']
       # query sql select count(*) from   
       # TokenUsageLimitExceededException



