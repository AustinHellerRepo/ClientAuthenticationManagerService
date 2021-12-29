from __future__ import annotations
import configparser
import time
from datetime import datetime
import os
import tempfile
from austin_heller_repo.client_authentication_manager import ServerMessengerFactory, ServerMessenger, ClientAuthenticationClientServerMessage, ClientAuthenticationManagerStructureFactory, OpenidAuthenticationConfiguration, OpenidConnectRedirectHttpServer, ClientMessengerFactory
from austin_heller_repo.socket import ServerSocketFactory, ClientSocketFactory
from austin_heller_repo.threading import SingletonMemorySequentialQueueFactory, start_thread
from austin_heller_repo.common import HostPointer


if "DOCKER_IP" in os.environ:
	docker_ip = os.environ["DOCKER_IP"]
	print(f"Found DOCKER_IP: {docker_ip}")
else:
	print(f"Failed to find DOCKER_IP")

config = configparser.ConfigParser()

config.read("./server_settings.ini")
server_socket_factory_config = config["ServerSocketFactory"]
to_client_packet_bytes_length = int(server_socket_factory_config["PacketBytesLength"])
listening_limit_total = int(server_socket_factory_config["ListeningLimitTotal"])
accept_timeout_seconds = float(server_socket_factory_config["AcceptTimeoutSeconds"])
host_address = server_socket_factory_config["HostAddress"]
host_port = int(server_socket_factory_config["HostPort"])
public_certificate_file_path = server_socket_factory_config["PublicCertificateFilePath"]
private_key_file_path = server_socket_factory_config["PrivateKeyFilePath"]
root_certificate_file_path = server_socket_factory_config["RootCertificateFilePath"]
http_server_config = config["HttpServer"]
http_server_port = int(http_server_config["Port"])
process_config = config["Process"]
sleep_seconds = float(process_config["SleepSeconds"])
is_interval_print = config.getboolean("Process", "IsIntervalPrint")
is_ssl_encrypted = config.getboolean("Process", "IsSslEncrypted")

config.read("./oauth_settings.ini")
google_config = config["Google"]
authentication_url = google_config["AuthorizationUrl"]
token_url = google_config["TokenUrl"]
scope = google_config["Scope"].split(",")
redirect_url = google_config["RedirectUrl"]
redirect_port = google_config["RedirectPort"]
jwt_pubkey_url = google_config["JwtPubKeyUrl"]
expected_issuer_url = google_config["ExpectedIssuerUrl"]
algorithm = google_config["Algorithm"]

config.read("./client_settings.ini")
client_credentials_config = config["ClientCredentials"]
client_id = client_credentials_config["ClientId"]
client_secret = client_credentials_config["ClientSecret"]

if not is_ssl_encrypted:
	print(f"Not SSL Encrypted")
	private_key_file_path = None
	public_certificate_file_path = None
	root_certificate_file_path = None
else:
	print(f"SSL Encrypted")

http_server = None  # type: OpenidConnectRedirectHttpServer


def http_server_thread_method():
	global http_server

	try:
		print(f"{datetime.utcnow()}: test: http_server_thread_method: start")

		http_server = OpenidConnectRedirectHttpServer(
			listen_port=http_server_port,
			client_authentication_manager_client_messenger_factory=ClientMessengerFactory(
				client_socket_factory=ClientSocketFactory(
					to_server_packet_bytes_length=to_client_packet_bytes_length,
					ssl_private_key_file_path=private_key_file_path,
					ssl_certificate_file_path=public_certificate_file_path,
					root_ssl_certificate_file_path=root_certificate_file_path
				),
				server_host_pointer=HostPointer(
					host_address=host_address,
					host_port=host_port
				),
				client_server_message_class=ClientAuthenticationClientServerMessage
			),
			authenticated_html_file_path="./resources/authenticated.html",
			favicon_file_path="./resources/favicon.ico"
		)
		print(f"{datetime.utcnow()}: test: http_server_thread_method: http_server.start()")
		http_server.start()
	except Exception as ex:
		print(f"{datetime.utcnow()}: test: http_server_thread_method: ex: {ex}")
	finally:
		print(f"{datetime.utcnow()}: test: http_server_thread_method: end")


http_server_thread = start_thread(http_server_thread_method)

time.sleep(1)

server_messenger_factory = ServerMessengerFactory(
	server_socket_factory=ServerSocketFactory(
		to_client_packet_bytes_length=to_client_packet_bytes_length,
		listening_limit_total=listening_limit_total,
		accept_timeout_seconds=accept_timeout_seconds,
		ssl_private_key_file_path=private_key_file_path,
		ssl_certificate_file_path=public_certificate_file_path,
		root_ssl_certificate_file_path=root_certificate_file_path
	),
	sequential_queue_factory=SingletonMemorySequentialQueueFactory(),
	local_host_pointer=HostPointer(
		host_address=host_address,
		host_port=host_port
	),
	client_server_message_class=ClientAuthenticationClientServerMessage,
	structure_factory=ClientAuthenticationManagerStructureFactory(
		openid_authentication_configuration=OpenidAuthenticationConfiguration(
			client_id=client_id,
			client_secret=client_secret,
			authentication_url=authentication_url,
			token_url=token_url,
			scope=scope,
			redirect_url=redirect_url,
			redirect_port=redirect_port,
			jwt_pubkey_url=jwt_pubkey_url,
			expected_issuer_url=expected_issuer_url,
			algorithm=algorithm
		)
	)
)

server_messenger = server_messenger_factory.get_server_messenger()

server_messenger.start_receiving_from_clients()

print(f"Listening on port: {host_port}")

try:
	print_index = 0
	start_datetime = datetime.utcnow()
	while True:
		time.sleep(sleep_seconds)
		if is_interval_print:
			print(f"{datetime.utcnow()}: {print_index}: {(datetime.utcnow() - start_datetime).total_seconds()} seconds elapsed")
			print_index += 1
finally:
	print(f"Stopping server messenger...")
	server_messenger.stop_receiving_from_clients()
	print(f"Stopping http server...")
	http_server.stop()
	print(f"Joining on http server thread...")
	http_server_thread.join()
	print(f"Done")
