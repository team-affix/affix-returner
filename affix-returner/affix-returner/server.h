#pragma once
#include <chrono>
#include <sstream>
#include "net-common/net_connection.h"
#include "affix-base/affix_base.h"
#include "cryptography/cryptography.h"
#include "asio/include/asio.hpp"
#include "affix-base/affix_base.h"

namespace affix_returner {

	using namespace asio;
	using namespace asio::ip;
	using namespace net_common;
	using affix_base::data::ptr;
	using affix_base::data::ts_deque;
	using std::stringstream;
	using CryptoPP::byte;
	using std::deque;
	using namespace affix_cryptography;

	class server {
	protected:
		io_context m_context;
		tcp::acceptor m_acceptor;
		ts_deque<ptr<connection>> m_connections;
		size_t m_current_connection_id = 0;
		RSA::PrivateKey m_private_key;

	public:
		server(uint16_t a_port, RSA::PrivateKey a_private_key) : m_acceptor(m_context, tcp::endpoint(tcp::v4(), a_port)), m_private_key(a_private_key) {
			async_accept();
		}

	protected:
		void async_accept() {
			m_acceptor.async_accept([&](error_code a_ec, tcp::socket a_sock) {
				if (a_ec)
					return;
				ptr<connection> l_connection = new connection(m_current_connection_id++, a_sock, 1024);
				m_connections.push_back(l_connection);
				async_accept();
			});
		}

	protected:
		void process_connection(deque<ptr<connection>>::iterator a_connection) {
			ptr<connection> l_connection = *a_connection;
			tcp::socket& l_sock = l_connection->socket();
			tcp::endpoint remote_ep = l_sock.remote_endpoint();
			
			uint32_t address = remote_ep.address().to_v4().to_ulong();
			uint16_t port = remote_ep.port();

			const auto p1 = std::chrono::system_clock::now();
			unsigned long long seconds_since_epoch = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();

			message result;
			result << seconds_since_epoch;
			result << address;
			result << port;
			result = sign_and_wrap_message(result);

			l_connection->async_send(result.serialize());

		}
		message sign_and_wrap_message(const message& a_message) {
			vector<byte> bytes = a_message.serialize();
			vector<byte> signature = rsa_sign(bytes, m_private_key);
			message result;
			result << bytes;
			result << signature;
			return result;
		}
		void on_remote_disconnect(connection& a_connection) {

		}
		void on_local_disconnect(connection& a_connection) {

		}

	};

}

