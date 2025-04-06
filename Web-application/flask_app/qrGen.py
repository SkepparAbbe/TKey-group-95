import pyotp
from io import BytesIO
import qrcode
import base64

def generate_qr(username):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="TKey")
    
    # Create a QR code with a white foreground and transparent background
    img = qrcode.make(uri)
    img = img.convert("RGBA")  # Convert to RGBA to support transparency
    pixels = img.load()
    
    # Change the QR code color to white and the background to transparent
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            if pixels[i, j][0] == 0:  # Black pixel
                pixels[i, j] = (255, 255, 255, 255)  # White pixel
            else:
                pixels[i, j] = (0, 0, 0, 0)  # Transparent pixel
    
    # Save to buffer
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    imgString = base64.b64encode(buffer.getvalue()).decode()
    
    return imgString, secret

def verify_totp(secret, user_input):
    totp = pyotp.TOTP(secret)
    return totp.verify(user_input)


if __name__ == "__main__":
    username = "example_user"
    imgString, secret = generate_qr(username)

    #test
    '''
    user_input = input("Ange TOTP från autentiseringsappen: ")
    if verify_totp(secret, user_input):
        print("Autentisering lyckades!")
    else:
        print("Autentisering misslyckades!")'
    '''