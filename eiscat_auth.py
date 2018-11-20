import csv
import os
import time


def is_admin(user):
    return user in open('superusers.txt').readlines()


def current_user():
    return os.environ['eduPersonUniqueID']


def is_authenticated():
    return 'Shib_Session_ID' in os.environ.keys()


def portal_authz(country, date, type):
    owners = 'UK NI NO SW FI CN'
    common = 'CP UP AA IPY'

    user = current_user()
    tld = user.split('.')[-1]

    # Domain to EISCAT country code used in SQL  DB.
    # ge is Georgia, ni is Nicaragua. Block.
    if tld == 'ge': return False
    if tld == 'ni': return False
    #  EISCAT codes differ for Germany, Sweden, Japan
    if tld == 'de': tld = 'ge'
    if tld == 'se': tld = 'sw'
    if tld == 'jp': tld = 'ni'

    institutes = {line[0]: line[1] for line in csv.reader(open("institutes.csv", "rb"))}
    persons = {line[0]: line[1] for line in csv.reader(open("persons.csv", "rb"))}

    if user.split('@')[-1] in institutes.keys():
        tld = institutes[user.split('@')[-1]]
    elif user in persons.keys():
        tld = persons[user]

    tld = tld.upper()

    return type == 'info' or \
        tld in country.upper() or \
            (tld in owners and (
                # EISCAT countries can download old data
                time.time() > date + 86400 * 366 or
                # EISCAT countries can download recent CP (UP. AA) data
                type in common.split(' '))
            )


def download_authz(*args):
    pass
