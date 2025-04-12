from flask import Flask, render_template, request
import random

app = Flask(__name__)
alphabet = "abcdefghijklmnopqrstuvwxyz"

def generate_key():
    return ''.join(random.sample(alphabet, len(alphabet)))

def mono_cipher(text, key, mode):
    result = ""
    text = text.lower()
    key = key.lower()
    if mode == "encrypt":
        for char in text:
            if char in alphabet:
                result += key[alphabet.index(char)]
            else:
                result += char
    else:
        for char in text:
            if char in key:
                result += alphabet[key.index(char)]
            else:
                result += char
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    text = ''
    key = ''
    mode = 'encrypt'

    if request.method == 'POST':
        text = request.form['text']
        mode = request.form['mode']
        if 'generate' in request.form:
            key = generate_key()
        else:
            key = request.form['key']
        if len(key) == 26:
            result = mono_cipher(text, key, mode)
        else:
            result = 'Key must be exactly 26 letters.'

    return render_template('index.html', result=result, text=text, key=key, mode=mode)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)