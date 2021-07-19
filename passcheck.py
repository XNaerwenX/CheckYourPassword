import requests
import hashlib
import sys
import itertools


def request_api_data(query_char):
    # query_char is the hashed piece of password
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# Check if the password exists in API response
def pwned_api_check(password):
    # encoding our password
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(*args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f"{password} was found {count} times... you should change your password.")
        else:
            print(f"{password} was NOT found!")
    return "Done!"


if __name__ == '__main__':
    with open("pass.txt", 'r') as file:
        args = []
        content = file.readlines()
        for item in content:
            args.append(item.strip().split())
        args = list(itertools.chain(*args))
    sys.exit(main(*args))
