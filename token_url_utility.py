import jwt
import furl 
from datetime import datetime, timedelta
from hashlib import sha256

class UrlValidationException(Exception): pass

class ExtendedUrl(furl.furl):

    def __create_token(self, user_id, exp_seconds, download_times, private_key):
        jwt_payload = {
            'sub' : str(sha256(user_id)),
            'exp' : datetime.utcnow() + timedelta(seconds=exp_seconds),
            'url' : self.__get_url_part_to_validate(),
            'd_times' : download_times
        }

        encoded_jwt = jwt.encode(jwt_payload, private_key, algorithm='RS256')
        return encoded_jwt

    def __get_url_part_to_validate(self):       
        return str(self.path) + '/' + self.query.encode()

    def inject_token(self, user_id, exp_seconds, download_times, private_key):
        encoded_jwt = self.__create_token(user_id, exp_seconds, download_times, private_key)
        path_within_token = [encoded_jwt] + self.path.segments 
        self.set(path=path_within_token)

    def validate(self, public_key):
        encoded_jwt = self.path.segments[0] 
        # pyjwt automatically validate signature and expiration time
        try: 
            token = jwt.decode(encoded_jwt, public_key)
            self.set(path=self.path.segments[1:])
            if (token['url'] != self.__get_url_part_to_validate()) :
                raise Exception('resource url mismatch') 
            # TODO: validate downloadtimes 
                
        except Exception as e:
            raise UrlValidationException(e.message)

initial_url = 'https://example.com:8443/dir1/sample_res.tar?par1=1&par2=2'

private_key = open('keys/private_key.pem','r').read()
public_key = open('keys/public_key.pem','r').read()

ext_url = ExtendedUrl(initial_url)

ext_url.inject_token('john', 60, 1, private_key)

download_url = ext_url.url

print (download_url)


ext_url2 = ExtendedUrl(download_url)

try:
    ext_url2.validate(public_key)
    print('validation succeeded')
except:
    print('validation failed')







