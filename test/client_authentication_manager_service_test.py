from __future__ import annotations
import unittest
from datetime import datetime
import uuid
import time
from austin_heller_repo.client_authentication_manager import ClientMessengerFactory, ClientAuthenticationClientServerMessage, UrlNavigationNeededResponseClientAuthenticationClientServerMessage, AuthenticationResponseClientAuthenticationClientServerMessage, OpenidAuthenticationRequestClientAuthenticationClientServerMessage
from austin_heller_repo.common import HostPointer
from austin_heller_repo.socket import ClientSocketFactory
from austin_heller_repo.threading import Semaphore


def get_default_client_messenger_factory() -> ClientMessengerFactory:
	return ClientMessengerFactory(
		client_socket_factory=ClientSocketFactory(
			to_server_packet_bytes_length=4096
		),
		server_host_pointer=HostPointer(
			host_address="localhost",
			host_port=35124
		),
		client_server_message_class=ClientAuthenticationClientServerMessage
	)


class ClientAuthenticationManagerServiceTest(unittest.TestCase):

	def test_initialize(self):

		client_messenger_factory = get_default_client_messenger_factory()

		self.assertIsNotNone(client_messenger_factory)

	def test_connect(self):

		client_messenger_factory = get_default_client_messenger_factory()

		client_messenger = client_messenger_factory.get_client_messenger()

		client_messenger.connect_to_server()

		time.sleep(1)

		client_messenger.dispose()

		time.sleep(1)

	def test_request_authentication(self):

		client_messenger_factory = get_default_client_messenger_factory()

		client_messenger = client_messenger_factory.get_client_messenger()

		client_messenger.connect_to_server()

		callback_total = 0
		authentication_response_client_server_message = None  # type: AuthenticationResponseClientAuthenticationClientServerMessage
		expected_external_client_id = str(uuid.uuid4())
		blocking_semaphore = Semaphore()
		blocking_semaphore.acquire()

		def callback(client_server_message: ClientAuthenticationClientServerMessage):
			nonlocal callback_total
			nonlocal authentication_response_client_server_message
			nonlocal expected_external_client_id

			callback_total += 1
			print(f"{datetime.utcnow()}: test: callback: client_server_message: {client_server_message.__class__.get_client_server_message_type()}")
			if callback_total == 1:
				self.assertIsInstance(client_server_message, UrlNavigationNeededResponseClientAuthenticationClientServerMessage)
				self.assertEqual(expected_external_client_id, client_server_message.get_external_client_id())
				client_server_message.navigate_to_url()
			elif callback_total == 2:
				self.assertIsInstance(client_server_message, AuthenticationResponseClientAuthenticationClientServerMessage)
				authentication_response_client_server_message = client_server_message  # store the message so that the null check will fail
				blocking_semaphore.release()
			else:
				raise Exception(f"Unexpected callback total: {callback_total}")

		found_exception = None

		def on_exception(exception: Exception):
			nonlocal found_exception
			if found_exception is None:
				found_exception = exception

		client_messenger.receive_from_server(
			callback=callback,
			on_exception=on_exception
		)

		client_messenger.send_to_server(
			request_client_server_message=OpenidAuthenticationRequestClientAuthenticationClientServerMessage(
				external_client_id=expected_external_client_id
			)
		)

		blocking_semaphore.acquire()
		blocking_semaphore.release()

		print(f"{datetime.utcnow()}: test: client_messenger.dispose(): start")

		client_messenger.dispose()

		print(f"{datetime.utcnow()}: test: client_messenger.dispose(): end")

		if found_exception is not None:
			raise found_exception

		self.assertEqual(2, callback_total)
		self.assertEqual(expected_external_client_id, authentication_response_client_server_message.get_external_client_id())
