import time
import json
import subprocess
from dotenv import dotenv_values
from user_agents import parse
from requests import get, exceptions as requests_exceptions
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

config = dotenv_values(".env")

api_key = config["API_KEY"]
chat_id = config["CHAT_ID"]

class FileModifiedHandler(FileSystemEventHandler):
    def on_modified(self, event):
        # Using subprocess to tail the log file
        tail_process = subprocess.Popen(
            ['tail', '-F', '/var/log/httpd/modsec_audit.log'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        for line in iter(tail_process.stdout.readline, ''):
            try:
                log_entry = json.loads(line.strip())

                # Extract relevant information from the log entry
                transaction = log_entry['transaction']
                client_ip = transaction['client_ip']  # Assuming client_ip is the attacker's IP
                user_agent = transaction['request']['headers'].get('user-agent', '')
                uri = transaction['request']['uri']
                http_code = transaction['response']['http_code']
                time_stamp = transaction['time_stamp']
                host = transaction['request']['headers'].get('host', '')

                messages = transaction.get('messages', [])

                # Check for critical severity messages
                for message in messages:
                    if message['details']['severity'] == 'CRITICAL':
                        msg = message['message']
                        data = message['details']['data']
                        severity = message['details']['severity']
                        rule_id = message['details']['ruleId']
                        file = message['details']['file']
                        line_number = message['details']['lineNumber']

                        # Parse the user-agent
                        ua = str(parse(user_agent))

                        # Format the message
                        log_message = (
                            "LAPORAN INSIDEN\n\n"
                            f"Tanggal kejadian: {time_stamp}\n"
                            f"Nama domain: {host}\n"
                            f"Metode: {transaction['request']['method']}\n"
                            f"URI: {uri}\n"
                            f"Response kode: {http_code}\n"
                            f"IP Penyerang: {client_ip}\n\n"
                            "Detail Indikasi:\n"
                            f"Message: {msg}\n"
                            f"Data: {data}\n"
                            f"Tingkat (Severity): {severity}\n"
                            f"Rule ID: {rule_id}\n"
                            f"File: {file}\n"
                            f"Line Number: {line_number}\n"
                        )

                        # Send the data to the bot with retry mechanism
                        max_retries = 3
                        for retry in range(max_retries):
                            try:
                                url = f'https://api.telegram.org/bot{api_key}/sendMessage?chat_id={chat_id}&text={log_message}'
                                response = get(url).json()
                                print(f"Critical log data sent to Telegram. Response: {response}")
                                break  # Break the retry loop if successful
                            except requests_exceptions.ConnectionError as e:
                                print(f"Connection error occurred: {e}")
                                if retry < max_retries - 1:
                                    print("Retrying...")
                                    time.sleep(5)  # Wait for 5 seconds before retrying
                                else:
                                    print("Max retries exceeded. Skipping this message.")

            except json.JSONDecodeError:
                print("Failed to decode JSON line from log.")
                continue

event_handler = FileModifiedHandler()
observer = Observer()
observer.schedule(event_handler, path='/var/log/httpd', recursive=False)  # Adjusted path to ModSecurity log directory

observer.start()
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt: 
    observer.stop()
observer.join()
