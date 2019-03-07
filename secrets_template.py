import os


def get_project():
    return '<PROJECT ID>'


def get_key():
    storage_key = os.path.expanduser('<SERVICE ACCOUNT KEY LOCATION>')
    return storage_key


if __name__ == '__main__':
    print(get_project())
    print(get_key())
