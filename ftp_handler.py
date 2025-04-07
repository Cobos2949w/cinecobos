from ftplib import FTP

def upload_image_via_ftp(image_file):
    ftp = FTP('ftp.cineapp.com')
    ftp.login('user', 'password')
    ftp.storbinary(f'STOR {image_file.filename}', image_file)
    ftp.quit()
    return f'http://ftp.cineapp.com/{image_file.filename}'