from flask import Flask, render_template, request, jsonify
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import os
import sys
import json
import base64
from datetime import datetime
import re
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

app = Flask(__name__)
CONFIG_FILE = 'config.json'

# ENCODING UTILITIES

def encode_data(data):
	if not data:
		return data
	return base64.b64encode(data.encode('utf-8')).decode()

def decode_data(encoded_data):
	if not encoded_data:
		return encoded_data
	try:
		return base64.b64decode(encoded_data.encode()).decode('utf-8')
	except:
		return encoded_data

# CONFIG MANAGEMENT

def load_config():
	if not os.path.exists(CONFIG_FILE):
		return {'username': '', 'password': '', 'custid': ''}
	try:
		with open(CONFIG_FILE, 'r') as f:
			config_data = json.load(f)
		if config_data.get('_encoded'):
			return {
				'username': decode_data(config_data.get('username', '')),
				'password': decode_data(config_data.get('password', '')),
				'custid': decode_data(config_data.get('custid', ''))
			}
		else:
			print("[INFO] Migrating plain text config to encoded format")
			return config_data
	except Exception as e:
		print(f"Error loading config: {e}")
		return {'username': '', 'password': '', 'custid': ''}

def save_config(username, password, custid):
	try:
		config = {
			'username': encode_data(username) if username else '',
			'password': encode_data(password) if password else '',
			'custid': encode_data(custid) if custid else '',
			'_encoded': True,
		}
	   
		with open(CONFIG_FILE, 'w') as f:
			json.dump(config, f, indent=2)
	   
		print("Configuration saved with encoding")
		return True
	except Exception as e:
		print(f"Error saving config: {e}")
		return False

# PHONE UTILITIES

def clean_and_validate_phone(phone):
	if not phone:
		return '', False, 'Phone number is required'
   
	original_phone = phone.strip()
	if original_phone.startswith('+'):
		digits_only = re.sub(r'\D', '', original_phone[1:])
		# Check for North American country code (1)
		if digits_only.startswith('1'):
			phone_part = digits_only[1:]
			if len(phone_part) == 10:
				return phone_part, True, None
			else:
				return '', False, f'Phone number {original_phone} is invalid - must be 10 digits after country code'
		else:
			# Non-North American country code
			country_code = digits_only[:3] if len(digits_only) > 10 else digits_only[:2]
			return '', False, f'Phone number {original_phone} does not belong to North America region (country code: +{country_code})'
	else:
		# No + prefix, remove all non-digit characters
		digits_only = re.sub(r'\D', '', original_phone)
		if len(digits_only) == 10:
			return digits_only, True, None
		elif len(digits_only) == 11 and digits_only.startswith('1'):
			return digits_only[1:], True, None  # Removes the '1' prefix
		elif len(digits_only) == 11:
			return '', False, f'Phone number {original_phone} does not belong to North America region (country code: {digits_only[0]})'
		else:
			return '', False, f'Phone number {original_phone} is invalid - must be 10 digits'

def format_phone_for_display(phone):
	if len(phone) == 10 and phone.isdigit():
		return f"({phone[:3]}) {phone[3:6]}-{phone[6:]}"
	return phone

# UNIFIED IOC VALIDATION

def clean_and_validate_ioc(ioc, case_type, mode='threat'):
	def defang(text):
		for old, new in [
			('[.]', '.'), ('(.)', '.'), ('hxxps://', 'https://'), ('hxxp://', 'http://'),
			('hxxps', 'https'), ('hxxp', 'http'), ('[//]', '//'), ('(//)', '//'),
			(':///', '://'), (' ://', '://'), (':/ /', '://'), (' ', '')
		]:
			text = text.replace(old, new)
		return text

	def is_valid_email(email):
		return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email.strip()))

	def is_valid_ip(ip):
		parts = ip.split('.')
		return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
   
	url_regex = re.compile(
		r'((http|https)://)?'   # optional scheme
		r'(([\w-]+\.)+)?'   # optional subdomains, including www
		r'([a-zA-Z]{2,})'   # top-level domain
		r'(:\d+)?'  # optional port
	)

	email_regex = re.compile(
		r'[a-zA-Z0-9._%+-]+'    #local part
		r'@'
		r'([a-zA-Z0-9-]+\.)+'   #subdomains(s) and domain
		r'[a-zA-Z{2,]'  #TLD
	)

	if not ioc and case_type.lower() == 'customer inquiry':
		return '', True, None, None
	if not ioc:
		return '', False, 'No IOC provided', None

	ioc = ioc.strip()
	cleaned = defang(ioc)
	ctype = case_type.lower()
	mode = mode.lower()

	# IOC type detection
	ioc_type = None
	if email_regex.search(cleaned) or '@' in cleaned and '.' in cleaned.split('@')[-1]:
		ioc_type = 'email'
	elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', cleaned):
		ioc_type = 'ip'
	elif url_regex.search(cleaned):
		# any(p in cleaned.lower() for p in ['http://', 'https://', 'hxxp://', 'hxxps://'])
		ioc_type = 'url'
	elif '.' in cleaned and ' ' not in cleaned and '/' not in cleaned:
		ioc_type = 'fqdn' if cleaned.count('.') >= 2 else 'domain'
	elif re.match(r'^\+?[\d\-\s\(\)]+$', cleaned) and '.' not in cleaned:
		digits_only = re.sub(r'\D','',cleaned)
		if len(digits_only) >= 10 and len(digits_only) <= 15:
			ioc_type = 'phone'
	else:
		ioc_type = 'unknown'

	if mode == 'monitor':
		if ioc_type in ['url', 'domain', 'fqdn', 'ip']:
			if ioc_type == 'url':
				parsed = urlparse(cleaned if cleaned.startswith(('http://', 'https://')) else 'https://' + cleaned)
				domain = parsed.hostname or parsed.path.split('/')[0].split(':')[0].lower()
			elif ioc_type in ['domain', 'fqdn']:
				domain = re.sub(r'^https?://', '', cleaned).split('/')[0].split(':')[0].lower()
			else:
				domain = cleaned
			return domain, True, None, 'domain'
		return '', False, 'Domain monitoring only accepts domains, URLs, or IPs', None

	if ctype in ['vishing', 'smishing']:
		if ioc_type != 'phone':
			return '', False, f'Expected phone number for {case_type}, got: {ioc}', None
		cleaned_phone, is_valid, err = clean_and_validate_phone(cleaned)
		return cleaned_phone, is_valid, err, 'phone'

	elif ctype in ['phishing', 'phishing redirect', 'crimeware']:
		if ioc_type not in ['url', 'domain', 'fqdn', 'ip']:
			return '', False, f'Expected URL, domain, or IP for {case_type}, got: {ioc}', None
		if ioc_type == 'ip':
			if not is_valid_ip(cleaned):
				return '', False, f'Invalid IP address: {ioc}', None
			return f'https://{cleaned}', True, None, 'url'
		url = cleaned if cleaned.startswith(('http://', 'https://')) else f'https://{cleaned}'
		try:
			parsed = urlparse(url)
			if not parsed.netloc:
				return '', False, f'Invalid URL: {ioc}', None
		except Exception:
			return '', False, f'Invalid URL: {ioc}', None
		return url, True, None, 'url'

	elif ctype == 'customer inquiry':
		if ioc_type == 'email':
			email = cleaned.lower()
			if is_valid_email(email):
				return email, True, None, 'email'
			return '', False, f'Invalid email: {ioc}', None
		elif ioc_type == 'phone':
			cleaned_phone, is_valid, err = clean_and_validate_phone(cleaned)
			return cleaned_phone, is_valid, err, 'phone'
		else:
			url = cleaned if cleaned.startswith(('http://', 'https://')) else f'https://{cleaned}'
			return url, True, None, 'url'

	else:
		if ioc_type == 'email':
			email = cleaned.lower()
			if is_valid_email(email):
				return email, True, None, 'email'
			return '', False, f'Invalid email: {ioc}', None
		elif ioc_type == 'phone':
			cleaned_phone, is_valid, err = clean_and_validate_phone(cleaned)
			return cleaned_phone, is_valid, err, 'phone'
		else:
			url = cleaned if cleaned.startswith(('http://', 'https://')) else f'https://{cleaned}'
			return url, True, None, 'url'

# API FUNCTIONS

def make_api_call(endpoint, method='GET', data=None, config=None):
	if config is None:
		config = load_config()
   
	if endpoint in ['brands', 'caseTypes', 'newCase'] or endpoint.startswith('attachFile'):
		if not config['username'] or not config['password']:
			return False, {'error': 'No credentials configured'}
		url = f'https://caseapi.phishlabs.com/v1/create/{endpoint}'
		use_auth = True
   
	elif endpoint.startswith('createincident'):
		if not config.get('custid'):
			return False, {'error': 'Customer ID required for Domain Monitor'}
		url = f'https://feed.phishlabs.com/{endpoint}'
		use_auth = False
   
	else:
		return False, {'error': 'Invalid endpoint'}
   
	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	}
   
	try:
		if method == 'GET':
			if use_auth:
				auth = HTTPBasicAuth(config['username'], config['password'])
				response = requests.get(url, auth=auth, headers=headers, timeout=3000, verify=False)
			else:
				response = requests.get(url, timeout=3000, verify=False)
		else:
			if use_auth:
				auth = HTTPBasicAuth(config['username'], config['password'])
				response = requests.post(url, json=data, auth=auth, headers=headers, timeout=3000, verify=False)
			else:
				response = requests.post(url, json=data, headers=headers, timeout=3000, verify=False)
	   
		if response.status_code in [200, 201, 202]:
			try:
				json_response = response.json()
				return True, json_response
			except:
				return True, {'response': response.text}
		elif response.status_code == 400:
			try:
				error_data = response.json()
				return False, error_data
			except:
				return False, {'error': f'Bad Request: {response.text}'}
		elif response.status_code == 401:
			return False, {'error': 'Unauthorized: Check credentials'}
		else:
			try:
				error_data = response.json()
				return False, {'error': error_data.get('errorMessage', response.text)}
			except:
				return False, {'error': f'HTTP {response.status_code}: {response.text}'}
	except requests.exceptions.Timeout:
		return False, {'error': 'Request timeout (15s)'}
	except requests.exceptions.ConnectionError:
		return False, {'error': 'Connection error'}
	except Exception as e:
		return False, {'error': str(e)}

def create_threat_case(ioc, brand, case_type, description, malware_type=None, config=None):
	if config is None:
		config = load_config()
	   
	if brand == 'Interac - TD EasyWeb':
		actual_brand = 'TD Easy Web'
	else:
		actual_brand = brand

	case_data = {
		"caseType": case_type,
		"brand": actual_brand
	}

	if case_type.lower() in ['vishing']:
		case_data["title"] = ioc
		formatted_phone = format_phone_for_display(ioc)
		desc_parts = [formatted_phone]
		if description:
			desc_parts.append(description)
		else:
			case_data["description"] = "\n\n".join(desc_parts)
	elif case_type.lower() == 'customer inquiry':
		case_data["title"] = ioc if ioc else "Customer Inquiry"
		case_data["description"] = description if description else "Customer Inquiry"
	else:
		# For all other case types
		case_data["title"] = f"{ioc} - <Interac>" if brand == 'Interac - TD EasyWeb' else ioc
		case_data["url"] = ioc if case_type.lower() in ['phishing', 'phishing redirect', 'crimeware', 'mobile'] else None

		desc_parts = []
		desc_parts.append(f"Malware Type: {malware_type}") if case_type.lower() == 'crimeware' and malware_type else None
		desc_parts.append(description) if description else None
		case_data["description"] = "\n\n".join(desc_parts) if desc_parts else "No description provided"
   
	data = {"newCase": case_data}
	return make_api_call('newCase', 'POST', data, config)

def create_monitor_case(domain, brand, threat_category, config=None):
	if config is None:
		config = load_config()
   
	if not config.get('custid'):
		return False, {'error': 'Customer ID required for Domain Monitor'}
   
	if brand == 'Interac - TD EasyWeb':
		title = f"{domain} - <Interac>"
		actual_brand = 'TD Easy Web'
	else:
		title = domain
		actual_brand = brand
   
	custid = str(config['custid']).strip('()\'\"')
	requestid = '1'
	catcode = int(threat_category)
	flags = '0'
   
	encoded_domain = urllib.parse.quote(domain, safe='')
   
	endpoint = (
		f"createincident?"
		f"custid={custid}&requestid={requestid}"
		f"&url={encoded_domain}&catcode={catcode}&flags={flags}"
		f"&product={urllib.parse.quote(actual_brand)}"
		f"&comment={urllib.parse.quote(title)}"
	)
   
	return make_api_call(endpoint, 'GET', None, config)

def attach_file_from_data(case_id, file_info, config=None):
	if config is None:
		config = load_config()
	if not file_info or not file_info.get('filename') or not case_id:
		return False, {'error': 'Missing file or case ID'}
	try:
		file_data = base64.b64encode(file_info['data']).decode()
		attach_data = {
			"attachment": {
				"fileName": file_info['filename'],
				"fileData": file_data,
				"mimeType": file_info['content_type']
			}
		}
		return make_api_call(f'attachFile/{case_id}', 'POST', attach_data, config)
	except Exception as e:
		return False, {'error': str(e)}

def process_case_result(ok, result, ioc, timestamp):
	if ok:
		# CT resp
		if 'createdCase' in result:
			# 201
			case_info = result['createdCase']
			return {
				'success': True,
				'status': 'Created',
				'caseNumber': case_info.get('caseNumber', 'N/A'),
				'caseId': case_info.get('caseId'),
				'copyText': f"{timestamp}\t{ioc}\t{case_info.get('caseNumber', 'N/A')}"
			}
		elif 'updatedCase' in result:
			# 200
			case_info = result['updatedCase']
			return {
				'success': True,
				'status': 'Updated',
				'caseNumber': case_info.get('caseNumber', 'N/A'),
				'caseId': case_info.get('caseId'),
				'copyText': f"{timestamp}\t{ioc}\t{case_info.get('caseNumber', 'N/A')}"
			}
		# TI resp
		elif 'IncidentId' in result and 'ErrorMessage' in result:
			incident_id = result.get('IncidentId', 0)
			error_msg = result.get('ErrorMessage', '')
			if incident_id > 0 and not error_msg:
				# 200
				return {
					'success': True,
					'status': 'Monitoring Case Created',
					'caseNumber': str(incident_id),
					'copyText': f"{timestamp}\t{ioc}\t{incident_id}"
				}
			elif incident_id == 0 and "incident already exists" in error_msg.lower():
				# 200
				return {
					'success': True,
					'status': 'Case already exists',
					'caseNumber': 'Exists',
					'copyText': f"{timestamp}\t{ioc}\tCase already exists",
					'isExisting': True
				}
			else:
				# 200 /w error
				return {
					'success': False,
					'status': f'Failed: {error_msg}',
					'caseNumber': 'N/A',
					'error': error_msg
				}
		else:
			# Generic success
			return {
				'success': True,
				'status': 'Processed',
				'caseNumber': 'N/A',
				'copyText': f"{timestamp}\t{ioc}\tProcessed"
			}
	else:
		error_msg = result.get('error', 'Unknown error')
		if 'messages' in result:
			messages = result.get('messages', [])
			if 'caseNumber' in result:
				existing_case_num = result.get('caseNumber', 'N/A')
			if any("Client submitted safelisted" in msg for msg in messages):
				return {
					'success': False,
					'status': 'Safelisted IOC - No case created',
					'caseNumber': "N/A",
					'copyText': f"{timestamp}\t{ioc}",
					'isExisting': False
				}
			if any("URL is assigned to active case" in msg for msg in messages):
				return {
					'success': True,
					'status': 'Case already exists',
					'caseNumber': str(existing_case_num),
					'copyText': f"{timestamp}\t{ioc}\t{existing_case_num}",
					'isExisting': True
				}
	   
		return {
			'success': False,
			'status': f'Failed process_case_result: {error_msg}',
			'caseNumber': 'N/A',
			'error': error_msg
		}

# ROUTE HANDLERS

@app.route('/')
def index():
	config = load_config()
	has_creds = bool(config['username'] and config['password'])
	brands, types = [], []
	if has_creds:
		ok, data = make_api_call('brands')
		if ok:
			brands = data.get('brands', [])
			if 'TD Easy Web' in brands:
				brands.append('Interac - TD EasyWeb')
	   
		ok, data = make_api_call('caseTypes')
		if ok:
			types = data.get('caseType', [])
	   
	return render_template('index.html', has_credentials=has_creds, brands=brands, case_types=types)

@app.route('/api/<action>', methods=['GET', 'POST'])
def api_handler(action):
	config = load_config()
   
	if action == 'test':
		if not config['username'] or not config['password']:
			return jsonify({'success': False, 'message': 'No credentials'})
		ok, _ = make_api_call('brands')
		return jsonify({'success': ok, 'message': 'Connected!' if ok else 'Failed'})
   
	elif action == 'refresh':
		brands, types = [], []
	   
		ok, data = make_api_call('brands')
		if ok:
			brands = data.get('brands', [])
			if 'TD Easy Web' in brands:
				brands.append('Interac - TD EasyWeb')
	   
		ok, data = make_api_call('caseTypes')
		if ok:
			types = data.get('caseType', [])
		   
		return jsonify({'success': True, 'brands': brands, 'case_types': types})
   
	elif action == 'settings':
		if request.method == 'GET':
			return jsonify({
				'username': config['username'],
				'hasPassword': bool(config['password']),
				'custid': config.get('custid', '')
			})
		else:
			data = request.json
			username = data.get('username', '').strip()
			password = data.get('password', '').strip()
			custid = data.get('custid', '').strip()
		   
			if not username:
				return jsonify({'success': False, 'message': 'Username required'})
		   
			if not password and config['password']:
				password = config['password']
			elif not password:
				return jsonify({'success': False, 'message': 'Password required'})
		   
			save_config(username, password, custid)
			return jsonify({'success': True})
   
	elif action == 'parse':
	   
		urls_text = request.json.get('urls', '')
	   
		if ',' in urls_text and '\n' not in urls_text:
			urls = [u.strip() for u in urls_text.split(',') if u.strip()]
		else:
			urls = [u.strip() for u in urls_text.split('\n') if u.strip()]
		return jsonify({'success': True, 'urls': urls})
   
	return jsonify({'success': False, 'message': 'Invalid action'})

@app.route('/process_cases', methods=['POST'])
def process_cases():
	config = load_config()
   
	if not config['username'] or not config['password']:
		return jsonify({'success': False, 'message': 'No credentials'})
   
	mode = request.form.get('case_mode', 'threat')
	case_type = request.form.get('case_type', '')
   
	iocs_list = request.form.getlist('iocs[]')
   
	if not iocs_list and case_type.lower() != 'customer inquiry':
		return jsonify({'success': False, 'message': 'No IOCs provided'})
   
	items = [item.strip() for item in iocs_list if item.strip()]
   
	if not items and case_type.lower() == 'customer inquiry':
		items = ['']  # Add empty item to process
   
	processed_items = []
	for item in items:
		validated_ioc, is_valid, error_msg, ioc_type = clean_and_validate_ioc(item, case_type, mode)
		if is_valid:
			processed_items.append({
				'value': validated_ioc,
				'original': item,
				'type': ioc_type or 'unknown'
			})
		else:
			processed_items.append({
				'value': item,
				'original': item,
				'error': error_msg,
				'is_invalid': True
			})
   
	valid_items = [item for item in processed_items if not item.get('is_invalid')]
	invalid_items = [item for item in processed_items if item.get('is_invalid')]
   
	if not valid_items:
		if invalid_items:
			error_details = []
			for item in invalid_items:
				error_details.append(f"'{item['original']}': {item.get('error', 'Unknown error')}")
		   
			return jsonify({
				'success': False,
				'message': f'No valid inputs found. Errors:\n' + '\n'.join(error_details[:5])
			})
		else:
			return jsonify({'success': False, 'message': 'No valid inputs found'})
   
	brand = request.form.get('brand')
	description = request.form.get('description')
	threat_cat = request.form.get('threat_category', '1201')
	malware_type = request.form.get('malware_type', '')  # For crimeware cases
   
	attachments = {}
	for i in range(len(valid_items)):
		files = request.files.getlist(f'attachment_{i}')
		if files:
			attachments[i] = []
			for file in files:
				if file and file.filename:
					file.seek(0)
					file_data = file.read()
					attachments[i].append({
						'filename': file.filename,
						'data': file_data,
						'content_type': file.content_type or 'application/octet-stream'
					})
   
	if len(valid_items) == 1:
		item = valid_items[0]
		timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	   
		try:
			if mode == 'monitor':
				ok, result = create_monitor_case(item['value'], brand, threat_cat, config)
			else:
				ok, result = create_threat_case(item['value'], brand, case_type, description, malware_type, config)
		   
			case_result = process_case_result(ok, result, item['value'], timestamp)
		   
			if case_result['success'] and case_result.get('caseId') and 0 in attachments:
				files_uploaded = 0
				for file_info in attachments[0]:
					ok_attach, _ = attach_file_from_data(case_result['caseId'], file_info, config)
					if ok_attach:
						files_uploaded += 1
				if files_uploaded > 0:
					case_result['status'] += f' + {files_uploaded} file(s) uploaded!'
		   
			return jsonify({
				'success': case_result['success'],
				'message': case_result['status'],
				'caseNumber': case_result.get('caseNumber', 'N/A'),
				'copyText': case_result.get('copyText', ''),
				'isSingle': True
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Error: {str(e)}',
				'caseNumber': 'N/A',
				'isSingle': True
			})
   
	def process_single_case(case_data):
		i, item, config, mode, brand, case_type, description, threat_cat, attachments, malware_type = case_data
	   
		if not item:
			return None
	   
		timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		# print(f"Processing item {i+1}: {item['value']}")
	   
		try:
			if mode == 'monitor':
				ok, result = create_monitor_case(item['value'], brand, threat_cat, config)
			else:
				ok, result = create_threat_case(item['value'], brand, case_type, description, malware_type, config)
		   
			case_result = process_case_result(ok, result, item['value'], timestamp)
		   
			status = case_result.get('status', 'Unknown')
			if case_result['success'] and case_result.get('caseId') and i in attachments:
				files_uploaded = 0
				for file_info in attachments[i]:
					ok_attach, _ = attach_file_from_data(case_result['caseId'], file_info, config)
					if ok_attach:
						files_uploaded += 1
				if files_uploaded > 0:
					status += f' + {files_uploaded} file(s)'
		   
			return {
				'ioc': item['value'],
				'caseNumber': case_result.get('caseNumber', 'N/A'),
				'status': status,
				'copyText': case_result.get('copyText', ''),
				'isSuccess': case_result['success'] and not case_result.get('isExisting', False),
				'isExisting': case_result.get('isExisting', False),
				'isFailed': not case_result['success'],
				'type': 'existing' if case_result.get('isExisting') else ('success' if case_result['success'] else 'failed'),
				'error': case_result.get('error', '') if not case_result['success'] else ''
			}
		   
		except Exception as e:
			print(f"Error processing {item['value']}: {str(e)}")
			return {
				'ioc': item['value'],
				'caseNumber': 'N/A',
				'status': f'Failed: {str(e)}',
				'copyText': '',
				'isSuccess': False,
				'isExisting': False,
				'isFailed': True,
				'type': 'failed',
				'error': str(e)
			}
   
	max_workers = min(100, len(valid_items))
	results = []
	successful_cases = []
	failed_cases = []
	existing_count = 0
   
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		case_data_list = [
			(i, item, config, mode, brand, case_type, description, threat_cat, attachments, malware_type)
			for i, item in enumerate(valid_items)
		]
	   
		future_to_case = {
			executor.submit(process_single_case, case_data): (i, item)
			for i, (case_data, item) in enumerate(zip(case_data_list, valid_items))
		}
	   
		for future in as_completed(future_to_case):
			try:
				result = future.result()
				if result:
					results.append(result)
				   
					if result['type'] == 'success':
						successful_cases.append({'ioc': result['ioc'], 'caseNumber': result['caseNumber']})
					elif result['type'] == 'existing':
						existing_count += 1
					elif result['type'] == 'failed':
						failed_cases.append({'ioc': result['ioc'], 'error': result.get('error', 'Unknown error')})
					   
			except Exception as e:
				i, item = future_to_case[future]
				print(f"Thread error for {item['value']}: {str(e)}")
				results.append({
					'ioc': item['value'],
					'caseNumber': 'N/A',
					'status': f'Thread error: {str(e)}',
					'copyText': '',
					'isSuccess': False,
					'isExisting': False,
					'isFailed': True
				})
				failed_cases.append({'ioc': item['value'], 'error': str(e)})
   
	for item in invalid_items:
		results.append({
			'ioc': item['original'],
			'caseNumber': 'N/A',
			'status': f"Invalid: {item['error']}",
			'copyText': '',
			'isSuccess': False,
			'isExisting': False,
			'isFailed': True
		})
		failed_cases.append({'ioc': item['original'], 'error': item['error']})
   
	try:
		results.sort(key=lambda x: next(i for i, item in enumerate(items) if item == x['ioc']))
	except:
		pass
   
	summary_parts = []
	if successful_cases:
		summary_parts.append(f'{len(successful_cases)} cases created')
	if failed_cases:
		summary_parts.append(f'{len(failed_cases)} failed')
	if existing_count:
		summary_parts.append(f'{existing_count} already exist')
   
	summary = ' | '.join(summary_parts) if summary_parts else 'No cases processed'
   
	return jsonify({
		'success': True,
		'message': f'Processed {len(results)} IOCs: {summary}',
		'results': results,
		'summary': {
			'successful': successful_cases,
			'failed': failed_cases,
			'existing': existing_count
		},
		'isSingle': False
	})

@app.route('/api/reset_config', methods=['POST'])
def reset_config():
	try:
		for file in [CONFIG_FILE]:
			if os.path.exists(file):
				os.remove(file)
		return jsonify({'success': True, 'message': 'Configuration reset successfully'})
	except Exception as e:
		return jsonify({'success': False, 'message': str(e)})

# MAIN
if __name__ == '__main__':
	print("Starting PhishLabs API Client...")
	if len(sys.argv) > 1 and sys.argv[1] == '--reset-config':
		print("Resetting configuration...")
		for file in [CONFIG_FILE]:
			if os.path.exists(file):
				os.remove(file)
				print(f"Removed {file}")
		print("Configuration reset complete. Please restart the application.")
		sys.exit(0)
	config = load_config()
	print("Credentials found!" if config['username'] and config['password'] else "No credentials configured.")
	app.run(debug=True, host='0.0.0.0', port=5005)
