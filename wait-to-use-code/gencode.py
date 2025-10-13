import pyotp

def gen(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

#passwd Ddj2389$&dfg!
if __name__ == "__main__":
    secret = 'A6JYIRPWPKJE7357YPNMQ2SR3GYN5V6X'
    print(gen(secret))