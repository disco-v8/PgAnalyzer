// ----------------------------------------------------------------------
// Protocol Analyzer for PostgreSQL -
// Purpose:
//     Various closing processing.
//
// Program:
//     Takeshi Kaburagi/MyDNS.JP    https://www.fvg-on.net/
//
// Usage:
//     ./evs_pganalyzer [./evserver.ini]
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// ヘッダ部分
// ----------------------------------------------------------------------
// --------------------------------
// インクルード宣言
// --------------------------------
// autoconf用宣言
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "evs_main.h"

// --------------------------------
// 定数宣言
// --------------------------------

// --------------------------------
// 型宣言
// --------------------------------

// --------------------------------
// 変数宣言
// --------------------------------

// ----------------------------------------------------------------------
// コード部分
// ----------------------------------------------------------------------
// --------------------------------
// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
// --------------------------------
void CLOSE_pgsql(struct ev_loop* loop, struct ev_io *watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = (struct EVS_ev_pgsql_t *)watcher;            // libevから渡されたwatcherポインタを、本来の拡張構造体ポインタとして変換する
	struct EVS_db_t                 *db_info = (struct EVS_db_t *)this_pgsql->db_info;

	struct timeval                  system_tv;
	struct tm                       *system_tm;

	// この接続のソケットを閉じる
	socket_result = close(this_pgsql->socket_fd);
	// ソケットのクローズ結果がエラーだったら
	if (socket_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): close(): Cannot socket close? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): close(): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// クライアント用テールキューからこの接続の情報を削除する
	TAILQ_REMOVE(&EVS_pgsql_tailq, this_pgsql, entries);

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): TAILQ_REMOVE(EVS_client_tailq): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// この接続のイベントを停止する
	ev_io_stop(loop, &this_pgsql->io_watcher);

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): ev_io_stop(): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL(%s) Close.\n", db_info->hostname);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// この接続のクライアント用拡張構造体のメモリ領域を開放する
	free(this_pgsql);

	return;
}

// --------------------------------
// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
// --------------------------------
void CLOSE_client(struct ev_loop* loop, struct ev_io *watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)watcher;   // libevから渡されたwatcherポインタを、本来の拡張構造体ポインタとして変換する

	struct timeval                  system_tv;
	struct tm                       *system_tm;

	// --------------------------------
	// 各種API関連
	// --------------------------------
	// SSLハンドシェイク中、もしくはSSL接続中なら
	if (this_client->ssl_status != 0)
	{
		// ----------------
		// OpenSSL(SSL_free : SSL接続情報のメモリ領域を開放)
		// ----------------
		SSL_free(this_client->ssl);
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL_free(): OK.\n", __func__, this_client->socket_fd);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}

	// この接続のソケットを閉じる
	socket_result = close(this_client->socket_fd);
	// ソケットのクローズ結果がエラーだったら
	if (socket_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): close(): Cannot socket close? errno=%d (%s)\n", __func__, this_client->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}
	// クライアント接続数を設定
	EVS_connect_num --;
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): close(): OK. Total=%d\n", __func__, this_client->socket_fd, EVS_connect_num);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// クライアント用テールキューからこの接続の情報を削除する
	TAILQ_REMOVE(&EVS_client_tailq, this_client, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): TAILQ_REMOVE(EVS_client_tailq): OK.\n", __func__, this_client->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// この接続のイベントを停止する
	ev_io_stop(loop, &this_client->io_watcher);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): ev_io_stop(): OK.\n", __func__, this_client->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Client(%s) Close.\n", this_client->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// この接続のクライアント用拡張構造体のメモリ領域を開放する
	free(this_client);

	return;
}

// --------------------------------
// 終了処理
// --------------------------------
int CLOSE_all(void)
{
	int                             close_result;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *pgsql_watcher;                     // PostgreSQL別設定用構造体ポインタ
	struct EVS_ev_client_t          *client_watcher;                    // クライアント別設定用構造体ポインタ
	struct EVS_ev_message_t         *message_info;                      // メッセージ用構造体ポインタ
	struct EVS_ev_server_t          *server_watcher;                    // サーバー別設定用構造体ポインタ
	struct EVS_timer_t              *timeout_watcher;                   // タイマー別構造体ポインタ
	struct EVS_db_t                 *db_list;                           // データベース別設定用構造体ポインタ
	struct EVS_port_t               *listen_port;                       // ポート別設定用構造体ポインタ

	// --------------------------------
	// PostgreSQL別クローズ処理
	// --------------------------------
	// PostgreSQL用テールキューからポート情報を取得して全て処理
	TAILQ_FOREACH (pgsql_watcher, &EVS_pgsql_tailq, entries)
	{
		// --------------------------------
		// API関連
		// --------------------------------
		// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
		CLOSE_pgsql(EVS_loop, (struct ev_io *)pgsql_watcher, close_result);
	}
	// クライアント用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_pgsql_tailq))
	{
		pgsql_watcher = TAILQ_FIRST(&EVS_pgsql_tailq);
		TAILQ_REMOVE(&EVS_pgsql_tailq, pgsql_watcher, entries);
		free(pgsql_watcher);
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_pgsql_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// クライアント別クローズ処理
	// --------------------------------
	// クライアント用テールキューからポート情報を取得して全て処理
	TAILQ_FOREACH (client_watcher, &EVS_client_tailq, entries)
	{
		// --------------------------------
		// API関連
		// --------------------------------
		// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
		CLOSE_client(EVS_loop, (struct ev_io *)client_watcher, close_result);
	}
	// クライアント用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_client_tailq))
	{
		client_watcher = TAILQ_FIRST(&EVS_client_tailq);
		TAILQ_REMOVE(&EVS_client_tailq, client_watcher, entries);
		free(client_watcher);
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_client_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// メッセージ別クローズ処理
	// --------------------------------
	// メッセージ用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_message_tailq))
	{
		// メッセージ情報を取得
		message_info = TAILQ_FIRST(&EVS_message_tailq);
		// メッセージ情報があるなら(まぁここでは確実にあるはずなんだけど…アイドルイベントで処理されてしまうかも!?)
		if (message_info != NULL)
		{
			// メッセージ解析処理
		
			// メッセージ用キューを削除
			TAILQ_REMOVE(&EVS_message_tailq, message_info, entries);
			free(message_info->message_ptr);
			free(message_info);
		}
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_message_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// サーバー別クローズ処理
	// --------------------------------
	// サーバー用テールキューからポート情報を取得して全て処理
	TAILQ_FOREACH (server_watcher, &EVS_server_tailq, entries)
	{
		// ----------------
		// ソケット終了(close : ソケットのファイルディスクリプタを閉じる)
		// ----------------
		close_result = close(server_watcher->socket_fd);
		// ソケットが閉じれなかったら
		if (close_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): close(fd=%d): Cannot socket close? errno=%d (%s)\n", __func__, server_watcher->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return -1;
		}
		// 該当ソケットのプロトコルファミリーがPF_UNIX(=UNIXドメインソケットなら
		if (server_watcher->socket_address.sa_un.sun_family == PF_UNIX)
		{
			// bindしたUNIXドメインソケットアドレスを削除
			close_result = unlink(server_watcher->socket_address.sa_un.sun_path);
			// UNIXドメインソケットアドレスが削除できなかったら
			if (close_result < 0)
			{
				snprintf(log_str, MAX_LOG_LENGTH, "%s(): unlink(%s): Cannot unlink? errno=%d (%s)\n", __func__, server_watcher->socket_address.sa_un.sun_path, errno, strerror(errno));
				logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
				return -1;
			}
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): unlink(%s): OK.\n", __func__, server_watcher->socket_address.sa_un.sun_path);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): close(fd=%d): OK.\n", __func__, server_watcher->socket_fd);
		logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
	}
	// サーバー用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_server_tailq))
	{
		server_watcher = TAILQ_FIRST(&EVS_server_tailq);
		TAILQ_REMOVE(&EVS_server_tailq, server_watcher, entries);
		free(server_watcher);
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_server_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// データベース別クローズ処理
	// --------------------------------
	// データベース用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_db_tailq))
	{
		db_list = TAILQ_FIRST(&EVS_db_tailq);
		TAILQ_REMOVE(&EVS_db_tailq, db_list, entries);
		free(db_list);
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_db_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// ポート別クローズ処理
	// --------------------------------
	// ポート用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_port_tailq))
	{
		listen_port = TAILQ_FIRST(&EVS_port_tailq);
		TAILQ_REMOVE(&EVS_port_tailq, listen_port, entries);
		free(listen_port);
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_port_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// libev関連終了処理 ※タイマー用に確保したメモリ領域のfree()を忘れずに
	// --------------------------------
	// タイマー用テールキューをすべて削除
	while (!TAILQ_EMPTY(&EVS_timer_tailq))
	{
		timeout_watcher = TAILQ_FIRST(&EVS_timer_tailq);
		TAILQ_REMOVE(&EVS_timer_tailq, timeout_watcher, entries);
		free(timeout_watcher);
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_REMOVE(EVS_timer_tailq): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// 各種設定関連終了処理 ※設定用に確保した文字列のメモリ領域のfree()を忘れずに
	// --------------------------------
	if (EVS_config.domain_socketfile != NULL)
	{
		free(EVS_config.domain_socketfile);
	}
	if (EVS_config.ssl_ca_file != NULL)
	{
		free(EVS_config.ssl_ca_file);
	}
	if (EVS_config.ssl_cert_file != NULL)
	{
		free(EVS_config.ssl_cert_file);
	}
	if (EVS_config.ssl_key_file != NULL)
	{
		free(EVS_config.ssl_key_file);
	}

	// --------------------------------
	// PIDファイル処理
	// --------------------------------
	// PIDファイルを削除
	close_result = unlink(EVS_config.pid_file);
	// PIDファイルが削除できなかったら
	if (close_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): unlink(%s): Cannot unlink? errno=%d (%s)\n", __func__, EVS_config.pid_file, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(EVS_config.pid_file);
		return -1;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): unlink(%s): OK.\n", __func__, EVS_config.pid_file);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
	free(EVS_config.pid_file);

	// 戻る
	return close_result;
}