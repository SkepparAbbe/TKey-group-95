import pyotp
from io import BytesIO
import qrcode
import base64

def generate_qr(username):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name ="TKey")
    img= qrcode.make(uri) 
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    imgString = base64.b64encode(buffer.getvalue()).decode()
    return (imgString, secret)

def verify_totp(secret, user_input):
    totp = pyotp.TOTP(secret)
    return totp.verify(user_input)


if __name__ == "__main__":
    username = "example_user"
    secret = generate_qr(username)


    #test
    '''
    user_input = input("Ange TOTP från autentiseringsappen: ")
    if verify_totp(secret, user_input):
        print("Autentisering lyckades!")
    else:
        print("Autentisering misslyckades!")'
    '''