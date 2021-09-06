#pragma once
#include <chrono>
#include <sstream>
#include "affix-base/affix_base.h"
#include "affix-base/transmission.h"
#include "affix-base/cryptography.h"
#include "asio.hpp"

#if 1
#define LOG(x) std::cout << x << std::endl
#else
#define LOG(x)
#endif

namespace affix_returner {

	using namespace asio;
	using namespace asio::ip;
	using namespace affix_base::networking;
	using namespace affix_base::cryptography;
	using namespace affix_base::timing;
	
	using affix_base::data::ptr;
	using affix_base::data::ts_deque;
	using std::stringstream;
	using CryptoPP::byte;
	using std::deque;

	const size_t RETURNER_INBOUND_DATA_SIZE = 25;

	struct timed_connection {
		size_t m_id = 0;
		udp::endpoint m_endpoint;
		uint64_t m_start_utc_time = 0;
		vector<byte> m_inbound_data;
		vector<byte> m_outbound_data;
		bool m_ready = false;
		bool m_processing = false;
		bool m_processed = false;
	};

	struct endpoint_information {
		uint32_t m_address;
		uint16_t m_port;
		string m_address_string;
	};

	class server {
	protected:
		io_service m_service;
		udp::socket m_socket;
		udp::endpoint m_remote_endpoint;
		vector<byte> m_received_data = vector<byte>(RETURNER_INBOUND_DATA_SIZE);
		ts_deque<timed_connection> m_connections;
		size_t m_current_connection_id = 0;
		RSA::PrivateKey m_private_key;
		uint64_t m_max_idle_seconds;
		std::thread m_service_thread;

	public:
		~server() {
			m_service.stop();
			m_service_thread.join();
		}
		server(uint16_t a_port, RSA::PrivateKey a_private_key, uint64_t a_max_idle_seconds) : m_socket(m_service), m_private_key(a_private_key), m_max_idle_seconds(a_max_idle_seconds) {
			m_socket.open(udp::v4());
			m_socket.bind(udp::endpoint(udp::v4(), a_port));
			async_receive();
			m_service_thread = std::thread([&] { m_service.run(); });
		}

	public:
		void process_connections() {

			deque<timed_connection>& l_deque = m_connections.get();

			for (int i = 0; i < l_deque.size(); i++)
				process_connection(l_deque.begin() + i);

			m_connections.unlock();

		}
		void clean_connections() {
			
			// WILL LOCK INTERNAL MUTEX OF m_connections
			deque<timed_connection>& l_connections = m_connections.get();

			for (int i = l_connections.size() - 1; i >= 0; i--)
				clean_connection(l_connections, l_connections.begin() + i);

			// UNLOCKS INTERNAL MUTEX OF m_connections
			m_connections.unlock();

		}
		
	protected:
		void async_receive() {
			m_socket.async_receive_from(asio::mutable_buffer(m_received_data.data(), m_received_data.size()), m_remote_endpoint, [&](error_code a_ec, size_t a_size) {

				if (a_ec) {
					async_receive();
					return;
				}

				deque<timed_connection>& l_connections = m_connections.get();

				auto l_connection = std::find_if(l_connections.begin(), l_connections.end(), [&](timed_connection& a_connection) {
					return a_connection.m_endpoint == m_remote_endpoint;
				});

				if (l_connection == l_connections.end()) {

					timed_connection l_timed_connection { m_current_connection_id++, m_remote_endpoint, utc_time() };
					l_connection = l_connections.insert(l_connections.end(), std::move(l_timed_connection));
					LOG("[ SERVER ] New connection, total connections: (" << l_connections.size() << ")");

				}

				if (l_connection->m_inbound_data.size() + a_size <= RETURNER_INBOUND_DATA_SIZE) {
					l_connection->m_inbound_data.insert(l_connection->m_inbound_data.end(), m_received_data.begin(), m_received_data.begin() + a_size);
				}

				l_connection->m_ready = l_connection->m_inbound_data.size() == RETURNER_INBOUND_DATA_SIZE;

				m_connections.unlock();
				async_receive();

			});
		}

	protected:
		// CALLED AFTER LOCK
		void clean_connection(deque<timed_connection>& a_connections, deque<timed_connection>::iterator a_connection) {
			
			uint64_t time_difference = utc_time() - a_connection->m_start_utc_time;

			if (a_connection->m_processed) {
				a_connections.erase(a_connection);
				return;
			}

			if (connection_expired(a_connection)) {
				LOG("[ SERVER ] Connection timed out after " << time_difference << " seconds; connection ID: " << a_connection->m_id << ".");
				a_connections.erase(a_connection);
				return;
			}

		}
		bool connection_expired(deque<timed_connection>::iterator a_connection) {
			uint64_t l_utc_time = utc_time();
			return l_utc_time - a_connection->m_start_utc_time >= m_max_idle_seconds;
		}

	protected:
		// CALLED AFTER LOCK
		void process_connection(deque<timed_connection>::iterator a_connection) {

			// CHECK IF CONNECTION IS NOT YET READY TO BE PROCESSED FIRST
			if (a_connection->m_processed || a_connection->m_processing || !a_connection->m_ready)
				return;

			a_connection->m_processing = true;

			endpoint_information ep_info;
			if (!try_get_endpoint_information(a_connection->m_endpoint, ep_info)) {
				return;
			}

			// WRITE ADDRESS AND PORT TO CONSOLE
			LOG("[ SERVER ] Connection address: " << ep_info.m_address_string << ", port: " << ep_info.m_port << ".");

			// RESPOND TO THE CONNECTION
			respond_to_connection(a_connection, ep_info);

		}
		bool try_get_endpoint_information(udp::endpoint& a_endpoint, endpoint_information& a_output) {

			// GET ADDRESS AND PORT FROM REMOTE ENDPOINT
			uint32_t l_address = a_endpoint.address().to_v4().to_ulong();
			uint16_t l_port = a_endpoint.port();

			a_output = { l_address, l_port, a_endpoint.address().to_string() };

			return true;

		}
		void respond_to_connection(deque<timed_connection>::iterator a_connection, endpoint_information& a_ep_info) {

			// CONSTRUCT RESPONSE MESSAGE
			message result;

			// ADD RANDOM DATA VECTOR TO THE MESSAGE DATA
			result << a_connection->m_inbound_data;

			// ADD (ADDRESS, PORT) PAIR TO THE MESSAGE DATA
			result << a_ep_info.m_address << a_ep_info.m_port;

			// ADD SIGNATURE TO THE MESSAGE DATA
			vector<byte> l_data = result.serialize();
			vector<byte> l_signature = rsa_sign(l_data, m_private_key);
			result << l_signature;

			// ADD OUTBOUND DATA TO GLOBAL
			a_connection->m_outbound_data = result.serialize();

			timed_connection& l_connection = *a_connection;

			// SEND MESSAGE
			m_socket.async_send_to(asio::buffer(a_connection->m_outbound_data.data(), a_connection->m_outbound_data.size()), a_connection->m_endpoint, [&] (error_code a_ec, size_t a_size) {

				if (a_ec) {
					LOG("[ SERVER ] Error sending response to client.");
				}

				l_connection.m_processed = true;

			});

		}

	};

}
