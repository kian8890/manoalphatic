from flask import Flask, render_template, request, redirect, url_for, flash
from base64 import b64decode
from Crypto.Hash import SHA1
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # لتفعيل الفلاش ميسجز

# نفس المتغيرات والقوائم من سكربتك الأصلي
valueMap = [
    'payload', 'payloadProxyURL', 'shouldNotWorkWithRoot', 'lockPayloadAndServers', 'expiryDate', 'hasNotes',
    'noteField2', 'sshAddress', 'onlyAllowOnMobileData', 'unlockRemoteProxy', 'unknown', 'vpnAddress',
    'sslSni', 'shouldConnectUsingSSH', 'udpgwPort', 'lockPayload', 'hasHWID', 'hwid', 'noteField1',
    'unlockUserAndPassword', 'sslAndPayloadMode', 'enablePassword', 'password'
]

xorList = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕']

def decrypt(contents, key):
    decryption_key = SHA1.new(data=bytes(key, 'utf-8')).digest()[:16]
    cipher = AES.new(decryption_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(contents)
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        # في حال لم يكن هناك padding
        return decrypted

def deobfuscate(contents):
    encrypted_string = contents.decode('utf-8')
    deobfuscated_contents = b''

    for index in range(len(encrypted_string)):
        deobfuscated_contents += bytes([ord(encrypted_string[index]) ^ ord(xorList[index % len(xorList)])])

    return b64decode(deobfuscated_contents)

def parse_key_entry(entry):
    key_list = entry.strip().split(':', 1)
    if len(key_list) != 2:
        return None
    return (bool(int(key_list[0])), key_list[1].strip())

def load_keys(filepath='keylist.txt'):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        lines = f.readlines()
    keys = [parse_key_entry(line) for line in lines if parse_key_entry(line) is not None]
    return keys

@app.route('/', methods=['GET', 'POST'])
def index():
    decrypted_data = None
    keys = load_keys()
    if request.method == 'POST':
        file = request.files.get('file')
        key_input = request.form.get('key_input', '').strip()
        use_raw = request.form.get('raw_output') == 'on'

        if not file:
            flash('Please upload a file to decrypt.', 'danger')
            return redirect(url_for('index'))

        encrypted_contents = file.read()

        # محاولة فك التشفير
        try:
            contents = deobfuscate(encrypted_contents)
        except Exception:
            contents = encrypted_contents

        original_contents = None

        if key_input:
            # استخدام المفتاح الذي أدخله المستخدم
            try:
                decrypted_bytes = decrypt(contents, key_input)
                original_contents = decrypted_bytes.decode('utf-8', errors='ignore')
            except Exception:
                flash('Wrong key or decryption failed.', 'danger')
                return redirect(url_for('index'))
        else:
            # تجربة المفاتيح من keylist.txt
            for key in keys:
                try:
                    decrypted_bytes = decrypt(contents, key[1])
                    original_contents = decrypted_bytes.decode('utf-8', errors='ignore')
                    if 'splitConfig' in original_contents:
                        flash(f'Successfully decrypted with key: {key[1]}', 'success')
                        break
                except Exception:
                    continue
            else:
                flash('Failed to decrypt with available keys.', 'danger')
                return redirect(url_for('index'))

        if not use_raw:
            config = original_contents.split('[splitConfig]')
            values = dict(zip(valueMap, config))
            decrypted_data = values
        else:
            decrypted_data = original_contents

    return render_template('index.html', decrypted_data=decrypted_data, keys=keys)

if __name__ == '__main__':
    app.run(debug=True)
