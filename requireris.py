import os

import hmac, base64, struct, hashlib, time, binascii, random
from flask import Flask, render_template, url_for, request, redirect

app = Flask(__name__)

## ERROR HANDLING

@app.errorhandler(500)
def internal_error(error):
	stylesheets = []
	stylesheets.append(url_for('static', filename='css/style.css'))
	return render_template('error.html',
							stylesheets=stylesheets,
							error='Error 500 : Internal Error')


@app.errorhandler(404)
def not_found(error):
	stylesheets = []
	stylesheets.append(url_for('static', filename='css/style.css'))
	return render_template('error.html',
							stylesheets=stylesheets,
							error='Error 404 : Page not found')

## OTP METHODS

@app.route('/hotp/<secret>/<intervals_no>')
def get_hotp_token(secret, intervals_no):
	try:
		secret = str(secret).translate(None, ' ')
		base64.decodestring(secret)
		key = base64.b32decode(secret, True)
		msg = struct.pack(">Q", intervals_no)
		h = hmac.new(key, msg, hashlib.sha1).digest()
		o = ord(h[19]) & 15
		h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
		h = str(h)
		# If shorter than 6 signs, requireris adds zeros to the beginning to reach a length of 6 chars
		if len(h) == 5:
			h = "0" + h
		return h
	except (binascii.Error, TypeError) as e:
		return 'Invalid secret'

@app.route('/totp/<secret>', methods=['GET'])
def get_totp_token(secret):
	return get_hotp_token(secret, intervals_no=int(time.time()) // 30)

@app.route('/register/<secret>',  methods=['GET', 'POST'])
def register(secret):
	error = 0
	stylesheets = []
	stylesheets.append(url_for('static', filename='css/style.css'))

	try:
		data = open('./static/data.txt', 'r')
	except IOError:
		error = 1
	if error == 0 and data.readline() == '':
		error = 1
	if request.method == 'POST' and secret != '':
		with open("./static/data.txt", "a") as myFile:
			if error == 1:
				myFile.write(request.form['username'] + ":" + secret)
			else:
				myFile.write("\n" + request.form['username'] + ":" + secret)
				data.close()
			return redirect('/')

	return render_template('register.html',
							stylesheets=stylesheets)
## INDEX PAGE

@app.route('/', methods=['GET', 'POST'])
def index():

## Fetching users
	error = 0
	users = []
	users_key = []
	
	try:
		data = open('./static/data.txt', 'r')
	except IOError:
		error = 1
	if (error == 0):
		f = data.read()
		data.close()
		f = f.replace('\n', ':')
		array = f.split(':')
		i = 0
		for values in array:
			if i % 2 == 0:
				users.append(values)
			else:
				users_key.append(values)
			i = i + 1
	if not users or users[0] == '':
		error = 1
	if not users_key or users_key[0] == '':
		error = 1

	rand = random.SystemRandom()
	chars = base64._b32alphabet.values()
	length = 32
	stylesheets = []
	stylesheets.append(url_for('static', filename='css/style.css'))
	if request.method == 'POST':
		f = request.form
		for key in f.keys():
			for value in f.getlist(key):
				if key == "secret":
					return render_template('show.html',
							old_secret=request.form['secret'],
							secret=get_totp_token(request.form['secret']),
							stylesheets=stylesheets)
				elif key == "users_list":
					return render_template('show.html',
							secret=get_totp_token(value),
							stylesheets=stylesheets)

## No users in database
	if (error == 1):
		return render_template('index.html',
								stylesheets=stylesheets,
								secret_example=(''.join(rand.choice(chars) for i in xrange(length))).lower(),
)
	else:
		return render_template('index.html',
								stylesheets=stylesheets,
								secret_example=(''.join(rand.choice(chars) for i in xrange(length))).lower(),
								users = users,
								users_key = users_key
)

if __name__ == '__main__':
	app.run(debug=True)
