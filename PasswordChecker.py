import requests  # use to send request
import hashlib  # to do SHA1 hashing
import sys

'''
url ='https://api.pwnedpasswords.com/range/' + '3866B'
res = requests.get(url)
'''


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'error fetching {res.status_code}, Check you API')
    return res


def read_response(res):  # display all the response hash
    print(res.text)


def getpassword_leak_count(hash, hash_to_check):  # takes the response and tail

    splited_hash = (line.split(':') for line in hash.text.splitlines())  # split with : and store in splited_hash
    for i, count in splited_hash:
        if i == hash_to_check:
            return count

    return 0


def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode(
        'utf-8')).hexdigest()).upper()  # takes a password generate a hash convert it into hexadecimal and then to Upper case
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    # read_response(response)
    return getpassword_leak_count(response, tail)


def main(password):
    pass_count = pwned_api_check(password)
    if int(pass_count) > 0:
        print(f'your password {password} was found {pass_count} time... You should change your password')
    else:
        print(f'password {password} was not found we can use it :)')

    return 'Done!'


if __name__ == '__main__':
    Enter_password = input('Please enter a password to check:- ')
    main(Enter_password)
