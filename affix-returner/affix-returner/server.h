#pragma once
#include "net-common/net_common.h"
#include "net-common/net_connection.h"
#include "affix-base/affix_base.h"
#include "asio.hpp"
#include <chrono>
#include <sstream>

namespace affix_returner {

	using namespace asio;
	using namespace asio::ip;
	using namespace net_common;
	using affix_base::data::ptr;
	using std::stringstream;

	class server {
	protected:
		io_context m_context;
		tcp::acceptor m_acceptor;
		ts_deque<ptr<connection>> m_connections;
		size_t m_current_connection_id = 0;

	public:
		server(uint16_t a_port) : m_acceptor(m_context, tcp::endpoint(tcp::v4(), a_port)) {
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
			stringstream remote_ep_ss;
			remote_ep_ss << remote_ep.address();
			remote_ep_ss << remote_ep.port();

			const auto p1 = std::chrono::system_clock::now();
			unsigned long long seconds_since_epoch = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();

			message result;
			result << seconds_since_epoch;
			result << ;

		}
		void on_remote_disconnect(connection& a_connection) {

		}
		void on_local_disconnect(connection& a_connection) {

		}

	};

}

