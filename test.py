
from token_url_utility import ExtendedUrl

initial_url = 'https://example.com:8443/dir1/sample_res.tar?par1=1&par2=2'

private_key = open('keys/private_key.pem','r').read()
public_key = open('keys/public_key.pem','r').read()


print('TEST1: it shoud validate')

ext_url = ExtendedUrl(initial_url)

ext_url.inject_token('john', 60, 1, private_key)

download_url = ext_url.url

print (download_url)

ext_url2 = ExtendedUrl(download_url)

if (ext_url2.is_valid(public_key)):
    print('validation succeeded')
else:
    print('validation failed')

try:
    claims = ext_url2.get_claims(public_key)
    print ('claims inside token')
    print (claims)
except Exception as e:
    print (e.message)

ext_url2.restore_original_url()

print('original URL: ' + ext_url2.url)

print('TEST2: it should give expiration error')

ext_url = ExtendedUrl(initial_url)

ext_url.inject_token('john', -1, 1, private_key)

download_url = ext_url.url

print (download_url)

ext_url2 = ExtendedUrl(download_url)

if (ext_url2.is_valid(public_key)):
    print('validation succeeded')
    try:
        claims = ext_url2.get_claims(public_key)
        print ('claims inside token')
        print (claims)
        ext_url2.restore_original_url()
        print('original URL: ' + ext_url2.url)
    except Exception as e:
        print (e.message)
else:
    print('validation failed')





