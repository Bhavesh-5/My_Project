from hashlib import md5, sha1
hash1 = md5(b"password").hexdigest()
hash2 = sha1(b"password").hexdigest()