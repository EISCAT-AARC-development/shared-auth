import unittest
from token_url_utility import ExtendedUrl, TokenUsageLimitExceededException, UrlValidationException
from jwt import ExpiredSignatureError
import os
import time

class TestExtendedUrl(unittest.TestCase):

    def _delete_download_log(self):
        logpath='download.log'
        if (os.path.exists(logpath)):
            os.remove(logpath)

    def setUp(self):
        self.initial_url = 'https://example.com:8443/dir1/sample_res.tar?par1=1&par2=2'
        self.private_key = open('keys/private_key.pem','r').read()
        self.public_key = open('keys/public_key.pem','r').read()
        
    def test_create_extended_url(self):
        self._delete_download_log()
        ext_url = ExtendedUrl(self.initial_url)

        token_max_usage = 1
        token_validity_secs = 60
        user = 'john'

        ext_url.inject_token(user, token_validity_secs, token_max_usage, self.private_key)
        download_url = ext_url.url

        self.assertIsNotNone(download_url)

    def test_create_extended_url_and_validate_it(self):
        self._delete_download_log()

        ext_url = ExtendedUrl(self.initial_url)

        token_max_usage = 1
        token_validity_secs = 60
        user = 'john'

        ext_url.inject_token(user, token_validity_secs, token_max_usage, self.private_key)

        download_url = ext_url.url

        ext_url2 = ExtendedUrl(download_url)

        self.assertTrue(ext_url2.is_valid(self.public_key))


    def test_create_extended_url_and_extract_claims(self):
        self._delete_download_log()

        ext_url = ExtendedUrl(self.initial_url)

        token_max_usage = 1
        token_validity_secs = 60
        user = 'john'

        ext_url.inject_token(user, token_validity_secs, token_max_usage, self.private_key)

        download_url = ext_url.url

        ext_url2 = ExtendedUrl(download_url)

        ext_url2.get_claims(self.public_key)

    def test_use_extended_url_more_than_allowed(self):
        self._delete_download_log()
        ext_url = ExtendedUrl(self.initial_url)

        token_max_usage = 2
        token_validity_secs = 60
        user = 'john'

        ext_url.inject_token(user, token_validity_secs, token_max_usage, self.private_key)

        download_url = ext_url.url

        ext_url2 = ExtendedUrl(download_url)
        ext_url2.get_claims(self.public_key)

        ext_url3 = ExtendedUrl(download_url)
        ext_url3.get_claims(self.public_key)

        ext_url4 = ExtendedUrl(download_url)
        self.assertRaises(TokenUsageLimitExceededException, ext_url4.get_claims, self.public_key)        

    def test_assert_signature_expiration_detection(self):
        self._delete_download_log()
        ext_url = ExtendedUrl(self.initial_url)

        token_max_usage = 1
        token_validity_secs = 1
        user = 'john'

        ext_url.inject_token(user, token_validity_secs, token_max_usage, self.private_key)

        download_url = ext_url.url

        time.sleep(2)

        ext_url2 = ExtendedUrl(download_url)

        self.assertRaises(ExpiredSignatureError, ext_url2.get_claims, self.public_key)


if __name__ == '__main__':
    unittest.main()
