from flask import Flask
from flask import request
from smtplib import SMTP_SSL
from email.mime.text import MIMEText

app = Flask(__name__)

EMAIL_USER = '23300031@uttt.edu.mx'
EMAIL_PASS = 'Dormilon00'  # Tu contraseña de aplicación

def send_email(subject, body, sender, recipients, password):
    msg = MIMEText(body, 'plain', 'utf-8')  # Especificamos UTF-8 aquí
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    try:
        with SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipients, msg.as_string())
        return "¡Mensaje enviado!"
    except Exception as e:
        return f"Error al enviar el correo: {e}"

@app.route('/enviar_correo_directo')
def enviar_correo_directo():
    subject = "Prueba de Correo Directo con Unicode desde Flask"
    body = "Este es el cuerpo del mensaje enviado directamente con smtplib y soporta caracteres Unicode como áéíóúñ. ¡Saludos desde México!"
    sender = EMAIL_USER
    recipients = [EMAIL_USER]  # Puedes cambiar el destinatario
    password = EMAIL_PASS
    result = send_email(subject, body, sender, recipients, password)
    return result

if __name__ == '__main__':
    app.run(debug=True)



