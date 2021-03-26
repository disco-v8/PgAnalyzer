// ----------------------------------------------------------------------
// Protocol Analyzer for PostgreSQL -
// Purpose:
//     Callback processing when an event occurs by libev.
//
// Program:
//     Takeshi Kaburagi/MyDNS.JP    https://www.fvg-on.net/
//
// Usage:
//     ./evs_pganalyzer [./evserver.ini]
// ----------------------------------------------------------------------

// evs_cbfunc.c はコールバック関数だけをまとめたファイルで、evs_init.cがごちゃごちゃするので分離している。
// evs_init.c からincludeされることを想定しているので、evs_main.hなどのヘッダファイルはincludeしていない。

// ----------------------------------------------------------------------
// ヘッダ部分
// ----------------------------------------------------------------------
// --------------------------------
// インクルード宣言
// --------------------------------

// --------------------------------
// 定数宣言
// --------------------------------
#define EVS_idle_message_check_interval     0.003                       // アイドルイベント時のメッセージのチェック間隔

// --------------------------------
// 型宣言
// --------------------------------

// --------------------------------
// 変数宣言
// --------------------------------
ev_tstamp   EVS_idle_message_check_lasttime = 0.;                       // メッセージの最終チェック日時
ev_tstamp   EVS_idle_client_check_lasttime = 0.;                        // クライアントの最終チェック日時

// ----------------------------------------------------------------------
// コード部分
// ----------------------------------------------------------------------
// --------------------------------
// シグナル処理(SIGHUP)のコールバック処理
// --------------------------------
static void CB_sighup(struct ev_loop* loop, struct ev_signal *watcher, int revents)
{
	char                            log_str[MAX_LOG_LENGTH];

	// イベントにエラーフラグが含まれていたら
	if (EV_ERROR & revents)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Invalid event!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): Catch SIGHUP!\n", __func__);
	logging(LOG_DIRECT, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	ev_break(loop, EVBREAK_CANCEL);                                     // わざわざこう書いてもいいけど、書かなくてもループは続けてくれる
}

// --------------------------------
// シグナル処理(SIGINT)のコールバック処理
// --------------------------------
static void CB_sigint(struct ev_loop* loop, struct ev_signal *watcher, int revents)
{
	char                            log_str[MAX_LOG_LENGTH];

	// イベントにエラーフラグが含まれていたら
	if (EV_ERROR & revents)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Invalid event!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): Catch SIGINT!\n", __func__);
	logging(LOG_DIRECT, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	ev_break(loop, EVBREAK_ALL);
}

// --------------------------------
// シグナル処理(SIGTERM)のコールバック処理
// --------------------------------
static void CB_sigterm(struct ev_loop* loop, struct ev_signal *watcher, int revents)
{
	char                            log_str[MAX_LOG_LENGTH];

	// イベントにエラーフラグが含まれていたら
	if (EV_ERROR & revents)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Invalid event!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): Catch SIGTERM!\n", __func__);
	logging(LOG_DIRECT, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	ev_break(loop, EVBREAK_ALL);
}

// --------------------------------
// アイドルイベント(メッセージ用キュー処理)のコールバック処理
// --------------------------------
static void CB_idle_message(struct ev_loop* loop, struct ev_idle *watcher, int revents)
{
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_message_t         *message_info;                                              // メッセージ用構造体ポインタ

	// --------------------------------
	// アイドル時に毎回毎回クライアントとの接続について処理するのはアホなので、0.x秒以上経過したらに検査するようにする。
	// --------------------------------
	if ((EVS_idle_message_check_lasttime - ev_now(loop) + EVS_idle_message_check_interval) < 0)
	{
		// --------------------------------
		// メッセージ解析処理 ※メッセージ用キューにメッセージがあるなら、かつその処理を10メッセージまでとする ※TAILQ_FIRST()してメッセージを一つ一つ取得する方がオーバーヘッドが発生するのて、一度このwhile()に来たら、メッセージ用キューが空になるまで解析したほうがよいみたい
		// --------------------------------
		while(!TAILQ_EMPTY(&EVS_message_tailq))
		{
			// メッセージ情報を取得
			message_info = TAILQ_FIRST(&EVS_message_tailq);
			// --------------------------------
			// メッセージ解析処理
			// --------------------------------
			// メッセージの方向がLOGLEVEL_MAX以下なら
			if (message_info->from_to <= LOGLEVEL_MAX)
			{
				// そのままログに出力(from_toはログレベル)
				logging(LOG_DIRECT, message_info->from_to, &(message_info->message_tv), NULL, NULL, message_info->message_ptr, strlen(message_info->message_ptr));
			}
			// 上記以外は、システム全体のログレベルがLOGLEVEL_LOG以下なら
			else if (EVS_config.log_level <= LOGLEVEL_LOG)
			{
				// メッセージの方向(LOGLEVEL_MAX以下:そのままログに出力, 101:Client->PgAnalyzer, 102:PgAnalyzer->Client, 111:PgAnalyzer->PostgreSQL, 112:PostgreSQL->PgAnalyzer)
				switch (message_info->from_to)
				{
					case 101:
////                        snprintf(log_str, MAX_LOG_LENGTH, "%s(): =%ld\n", __func__, message_info->message_tv.tv_sec);
////                        logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
						// クライアントクエリメッセージ解析処理 ※この処理はアイドルイベント時にのみ、溜まっているメッセージ用キューのログへの出力として呼び出される。なので、クライアントの状態は2より大きいはず。
						API_pgsql_client_message(message_info);
						break;
					case 102:
						snprintf(log_str, MAX_LOG_LENGTH, "%s(): =%ld\n", __func__, message_info->message_tv.tv_sec);
						logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
						break;
					case 111:
						snprintf(log_str, MAX_LOG_LENGTH, "%s(): _sec=%ld\n", __func__, message_info->message_tv.tv_sec);
						logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
						break;
					case 112:
////                        snprintf(log_str, MAX_LOG_LENGTH, "%s(): Message Found!! PostgreSQL->PgAnalyzer, message_tv.tv_sec=%ld\n", __func__, message_info->message_tv.tv_sec);
////                        logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
						// PostgreSQL側メッセージ処理 ※この処理はアイドルイベント時にのみ、溜まっているメッセージ用キューのログへの出力として呼び出される。なので、PostgreSQLの状態は2より大きいはず。
						API_pgsql_server_message(message_info);
						break;
					default:
						snprintf(log_str, MAX_LOG_LENGTH, "%s(): Message Found!! from_to=%02d!? message_tv.tv_sec=%ld\n", __func__, message_info->from_to, message_info->message_tv.tv_sec);
						logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
				}
			}
			// メッセージ用キューを削除
			TAILQ_REMOVE(&EVS_message_tailq, message_info, entries);
			free(message_info->message_ptr);
			free(message_info);
		}
		// イベントループの日時を現在の日時に更新
		ev_now_update(loop);
		// 最終アイドルチェック日時を更新
		EVS_idle_message_check_lasttime = ev_now(loop);

		// もしメッセージ用キューが空っぽなら
		if (TAILQ_EMPTY(&EVS_message_tailq))
		{
			// このアイドルイベントを停止する(再びメッセージ用キューにデータが溜まれば開始する)
			ev_idle_stop(loop, watcher);
		}
	}
}

// ----------------
// タイマーイベントのコールバック処理
// ----------------
static void CB_timeout(struct ev_loop* loop, struct ev_timer *watcher, int revents)
{
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_timer_t              *this_timeout;                      // タイマー別構造体ポインタ
	struct EVS_ev_client_t          *client_watcher;                    // クライアント別設定用構造体ポインタ
	struct EVS_ev_pgsql_t           *pgsql_watcher;                     // PostgreSQL別設定用構造体ポインタ

	ev_tstamp                       nowtime = 0.;                       // タイムアウト日時

	// イベントループの日時を現在の日時に更新
	ev_now_update(loop);
	nowtime = ev_now(loop);

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): Timeout check start! ev_now=%.0f\n", __func__, nowtime);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// タイマー別処理
	// --------------------------------
	// タイマー用テールキューに登録されているタイマーを確認
	TAILQ_FOREACH (this_timeout, &EVS_timer_tailq, entries)
	{
		// 該当タイマーがすでにタイムアウトしていたら
		if (ev_now(loop) > this_timeout->timeout)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Timeout!!!\n", __func__);
			logging(LOG_QUEUEING, LOGLEVEL_WARN, NULL, NULL, NULL, log_str, strlen(log_str));
		}
		else
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Not Timeout!?\n", __func__);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
	}
	// ----------------
	// 無通信タイムアウトチェックをする(=1:有効)なら
	// ----------------
	if (EVS_config.nocommunication_check == 1)
	{
		// --------------------------------
		// クライアント別クローズ処理
		// --------------------------------
		// クライアント用テールキューからポート情報を取得して全て処理
		TAILQ_FOREACH (client_watcher, &EVS_client_tailq, entries)
		{
			// 無通信タイマーの経過時間がすでにタイムアウトしていたら
			if ((client_watcher->last_activity + EVS_config.nocommunication_timeout) < nowtime)
			{
				snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Client Timeout!!!\n", __func__, client_watcher->socket_fd);
				logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
				// ----------------
				// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
				// ----------------
				CLOSE_client(loop, (struct ev_io *)client_watcher, revents);
			}
		}
		// --------------------------------
		// PostgreSQL別クローズ処理
		// --------------------------------
		// PostgreSQL用テールキューからポート情報を取得して全て処理
		TAILQ_FOREACH (pgsql_watcher, &EVS_pgsql_tailq, entries)
		{
			// 無通信タイマーの経過時間がすでにタイムアウトしていたら
			if ((pgsql_watcher->last_activity + EVS_config.nocommunication_timeout) < nowtime)
			{
				snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): PostgreSQL Timeout!!!\n", __func__, pgsql_watcher->socket_fd);
				logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
				// ----------------
				// PostgreSQL接続終了処理(イベントの停止、PostgreSQLキューからの削除、SSL接続情報開放、ソケットクローズ、PostgreSQL情報開放)
				// ----------------
				CLOSE_pgsql(loop, (struct ev_io *)pgsql_watcher, revents);
			}
		}
	}
	// イベントループの日時を現在の日時に更新
	ev_now_update(loop);
	// 最終アイドルチェック日時を更新
	EVS_idle_client_check_lasttime = nowtime;

	// ----------------
	// タイマーオブジェクトに対して、タイムアウト確認間隔(timer_checkintval秒)、そして繰り返し回数(0回)を設定する(つまり次のタイマーを設定している)
	// ----------------
	ev_timer_set(&timeout_watcher, EVS_config.timer_checkintval, 0);    // ※&timeout_watcherの代わりに&watcherとしても同じこと
	ev_timer_start(loop, &timeout_watcher);
}

// --------------------------------
// ソケット受信(recv : ソケットに対してメッセージが送られてきたときに発生するイベント)のコールバック処理
// --------------------------------
static void CB_recv(struct ev_loop* loop, struct ev_io *watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)watcher;   // libevから渡されたwatcherポインタを、本来の拡張構造体ポインタとして変換する

	// イベントにエラーフラグが含まれていたら
	if (EV_ERROR & revents)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Invalid event!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): OK. ssl_status=%d\n", __func__, this_client->socket_fd, this_client->ssl_status);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// 無通信タイムアウトチェックをする(=1:有効)なら
	// ----------------
	if (EVS_config.nocommunication_check == 1)
	{
		ev_now_update(loop);                                            // イベントループの日時を現在の日時に更新
		this_client->last_activity = ev_now(loop);                      // 最終アクティブ日時(監視対象が最後にアクティブとなった日時)を設定する
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): last_activity=%.0f\n", __func__, this_client->socket_fd, this_client->last_activity);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}

	// ----------------
	// 非SSL通信(=0)なら
	// ----------------
	if (this_client->ssl_status == 0)
	{
		// クライアント毎の状態については、1:開始メッセージ受信中、2:クエリ受信中かは気にしない→クライアントから受信したメッセージは全てPostgreSQLに送信するから
		// ただし、開始処理が完了(=PostgreSQLからReadyForQueryを受ける)したら、2:クエリ受信中に移行すること

		// ----------------
		// ソケット受信(recv : ソケットのファイルディスクリプタから、受信データ格納開始ポインタに受信可能データ長だけメッセージを受信する。(ノンブロッキングにするなら0ではなくてMSG_DONTWAIT)
		// ----------------
		socket_result = recv(this_client->socket_fd, (void *)this_client->recv_buf, MAX_RECV_BUF_LENGTH, 0);

		// 読み込めたメッセージ量が負(<0)だったら(エラーです)
		if (socket_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot recv message? errno=%d (%s)\n", __func__, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// クライアント接続終了処理(各種API関連情報解放、SSL接続情報開放、ソケットクローズ、クライアントキューからの削除、イベントの停止)
			// ----------------
			CLOSE_client(loop, (struct ev_io *)this_client, revents);
			return;
		}
		// 読み込めたメッセージ量が0だったら(切断処理をする)
		else if (socket_result == 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): socket_result == 0.\n", __func__, this_client->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
			// ----------------
			CLOSE_client(loop, (struct ev_io *)this_client, revents);
			return;
		}

		// クライアント毎の状態が、3:クエリデータ待ちでないなら
		if (this_client->client_status != 3)
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_client->recv_len = socket_result;
			this_client->recv_buf[this_client->recv_len] = '\0';
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Recieved %d bytes, recv_len=%d. A\n", __func__, this_client->socket_fd, socket_result, this_client->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
		// クライアント毎の状態が、3:クエリデータ待ちなら
		else
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_client->recv_len += socket_result;
			this_client->recv_buf[this_client->recv_len] = '\0';
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Recieved %d bytes, recv_len=%d. B\n", __func__, this_client->socket_fd, socket_result, this_client->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
	}
	// ----------------
	// SSLハンドシェイク中なら
	// ----------------
	else if (this_client->ssl_status == 1)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL/TLS handshake START!\n", __func__, this_client->socket_fd);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

		// ----------------
		// OpenSSL(SSL_accept : SSL/TLSハンドシェイクを開始)
		// ----------------
		socket_result = SSL_accept(this_client->ssl);
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL_accept(): socket_result=%d.\n", __func__, this_client->socket_fd, socket_result);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

		// SSL/TLSハンドシェイクの結果コードを取得
		socket_result = SSL_get_error(this_client->ssl, socket_result);
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL_get_error(): socket_result=%d.\n", __func__, this_client->socket_fd, socket_result);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

		// SSL/TLSハンドシェイクの結果コード別処理分岐
		switch (socket_result)
		{
			case SSL_ERROR_NONE : 
				// エラーなし(ハンドシェイク成功)
				// SSL接続中に設定
				this_client->ssl_status = 2;
				snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL/TLS handshake OK.\n", __func__, this_client->socket_fd);
				logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
				break;
			case SSL_ERROR_SSL :
			case SSL_ERROR_SYSCALL :
				// SSL/TLSハンドシェイクがエラー
				snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot SSL/TLS handshake!? %s\n", __func__, this_client->socket_fd, ERR_reason_error_string(ERR_get_error()));
				logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
				// ----------------
				// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
				// ----------------
				CLOSE_client(loop, (struct ev_io *)this_client, revents);
				break;
			case SSL_ERROR_WANT_READ :
			case SSL_ERROR_WANT_WRITE :
				// まだハンドシェイクが完了するほどのメッセージが届いていなようなので、次のメッセージ受信イベントを待つ
				// ※たいていはSSLポートに対してSSLではない接続が来た時にこの分岐処理となる
				break;
		}
		// ----------------
		// SSLハンドシェイク処理が終了したら、いったんコールバック関数から抜ける(メッセージが来るのは次のイベント)
		// ----------------
		return;
	}
	// ----------------
	// SSL接続中なら
	// ----------------
	else if (this_client->ssl_status == 2)
	{
		// ----------------
		// OpenSSL(SSL_read : SSLデータ読み込み)
		// ----------------
		socket_result = SSL_read(this_client->ssl, (void *)this_client->recv_buf, MAX_RECV_BUF_LENGTH);

		// 読み込めたメッセージ量が負(<0)だったら(エラーです)
		if (socket_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL_read(): Cannot read decrypted message!?\n", __func__, this_client->socket_fd, ERR_reason_error_string(ERR_get_error()));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
			// ----------------
			CLOSE_client(loop, (struct ev_io *)this_client, revents);
			return;
		}
		// 読み込めたメッセージ量が0だったら(切断処理をする)
		if (socket_result == 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): socket_result == 0.\n", __func__, this_client->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
			// ----------------
			CLOSE_client(loop, (struct ev_io *)this_client, revents);
			return;
		}

		// クライアント毎の状態が、3:クエリデータ待ちでないなら
		if (this_client->client_status != 3)
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_client->recv_len = socket_result;
			this_client->recv_buf[this_client->recv_len] = '\0';
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Recieved %d bytes, recv_len=%d. C\n", __func__, this_client->socket_fd, socket_result, this_client->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
		// クライアント毎の状態が、3:クエリデータ待ちなら
		else
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_client->recv_len += socket_result;
			this_client->recv_buf[this_client->recv_len] = '\0';
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Recieved %d bytes, recv_len=%d. D\n", __func__, this_client->socket_fd, socket_result, this_client->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
	}

	// --------------------------------
	// API関連
	// --------------------------------
	// API開始処理(クライアント別処理分岐)
	socket_result = API_start(this_client);

	// APIの処理結果がエラー(!=0)だったら(切断処理をする)
	if (socket_result != 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): API ERROR!? socket_result=%d\n", __func__, this_client->socket_fd, socket_result);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		// ----------------
		// クライアント接続終了処理(イベントの停止、クライアントキューからの削除、SSL接続情報開放、ソケットクローズ、クライアント情報開放)
		// ----------------
		CLOSE_client(loop, (struct ev_io *)this_client, revents);

		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		return;
	}

	// アイドルイベント開始(メッセージ用キュー処理)
	ev_idle_start(loop, &idle_message_watcher);
	return;
}

// --------------------------------
// SSL接続情報生成＆ファイルディスクリプタ紐づけ
// --------------------------------
void CB_accept_SSL(struct EVS_ev_client_t * client_watcher)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	// ----------------
	// OpenSSL(SSL_new : SSL設定情報を元に、SSL接続情報を生成)
	// ----------------
	client_watcher->ssl = SSL_new(EVS_ctx);
	// SSL設定情報を元に、SSL接続情報を生成がエラーだったら
	if (client_watcher->ssl == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(client fd=%d): SSL_new(): Cannot get new SSL structure!? %s\n", __func__, client_watcher->socket_fd, ERR_reason_error_string(ERR_get_error()));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(client_watcher);
		return;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(client fd=%d): SSL_new(): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// OpenSSL(SSL_set_fd : 接続してきたソケットファイルディスクリプタを、SSL_set_fd()でSSL接続情報に紐づけ)
	// ----------------
	// 接続してきたソケットファイルディスクリプタを、SSL_set_fd()でSSL接続情報に紐づけがエラーだったら
	if (SSL_set_fd(client_watcher->ssl, client_watcher->socket_fd) == 0)
	{
		// ここでもソケットをクローズをしたほうがいいかな？それともソケットを再設定したほうがいいかな？
		snprintf(log_str, MAX_LOG_LENGTH, "%s(client fd=%d): SSL_set_fd(): Cannot SSL socket binding!? %s\n", __func__, client_watcher->socket_fd, ERR_reason_error_string(ERR_get_error()));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(client_watcher);
		return;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(client fd=%d): SSL_set_fd(): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
}

// --------------------------------
// IPv6ソケットアクセプト(accept : ソケットに対して接続があったときに発生するイベント)のコールバック処理
// --------------------------------
static void CB_accept_ipv6(struct ev_loop* loop, struct EVS_ev_server_t * server_watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	int                             nonblocking_flag = 0;                                       // ノンブロッキング設定(0:非対応、1:対応))

	struct sockaddr_in6             client_sockaddr_in6;                                        // IPv6用ソケットアドレス構造体
	socklen_t                       client_sockaddr_len = sizeof(client_sockaddr_in6);          // IPv6ソケットアドレス構造体のサイズ (バイト単位)
	struct EVS_ev_client_t          *client_watcher = NULL;                                     // クライアント別設定用構造体ポインタ

	// ----------------
	// ソケットアクセプト(accept : リッスンポートに接続があった)
	// ----------------
	socket_result = accept(server_watcher->socket_fd, (struct sockaddr *)&client_sockaddr_in6, &client_sockaddr_len);
	// アクセプトしたソケットのディスクリプタがエラーだったら
	if (socket_result < 0)
	{
		// ここでもソケットをクローズをしたほうがいいかな？それともソケットを再設定したほうがいいかな？
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot socket accepting? Total=%d, errno=%d (%s)\n", __func__, server_watcher->socket_fd, EVS_connect_num, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}
	// クライアント接続数を設定
	EVS_connect_num ++;
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): OK. client fd=%d, Total=%d\n", __func__, server_watcher->socket_fd, socket_result, EVS_connect_num);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// クライアント別設定用構造体ポインタのメモリ領域を確保
	client_watcher = (struct EVS_ev_client_t *)calloc(1, sizeof(struct EVS_ev_client_t));
	// メモリ領域が確保できなかったら
	if (client_watcher == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot calloc client_watcher's memory? errno=%d (%s)\n", __func__, server_watcher->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	// クライアント別設定用構造体ポインタにアクセプトしたソケットの情報を設定
	client_watcher->socket_fd = socket_result;                                                                      // ディスクリプタを設定する
	getpeername(client_watcher->socket_fd, (struct sockaddr *)&client_sockaddr_in6, &client_sockaddr_len);          // クライアントのアドレス情報を取得しなおす(し直さないと、IPv6でのローカル接続時に惑わされることになるョ)

	// クライアントのアドレスを文字列として格納
	inet_ntop(PF_INET6, (void *)&client_sockaddr_in6.sin6_addr, client_watcher->addr_str, sizeof(client_watcher->addr_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): inet_ntop(PF_INET6): Client address=%s\n", __func__, client_watcher->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));


	// PostgreSQLプロトコルの場合には、STARTTLS的な感じで、平文から暗号化通信になるので、ここまではまだ何かをすることはない


	// ----------------
	// クライアントとの接続ソケットのノンブロッキングモードをnonblocking_flagに設定する
	// ----------------
	socket_result = ioctl(client_watcher->socket_fd, FIONBIO, &nonblocking_flag);
	// 設定ができなかったら
	if (socket_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): ioctl(): Cannot set Non-Blocking mode!? errno=%d (%s)\n", __func__, client_watcher->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(client_watcher);
		return;
	}

	// ----------------
	// 無通信タイムアウトチェックをする(=1:有効)なら
	// ----------------
	if (EVS_config.nocommunication_check == 1)
	{
		ev_now_update(loop);                                                // イベントループの日時を現在の日時に更新
		client_watcher->last_activity = ev_now(loop);                       // 最終アクティブ日時(監視対象が最後にアクティブとなった日時)を設定する
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): last_activity=%.0f\n", __func__, client_watcher->socket_fd, client_watcher->last_activity);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}

	// --------------------------------
	// API関連
	// --------------------------------
	// クライアント毎の状態を、0:接続待ちに設定
	client_watcher->client_status = 0;
	// クライアントからのSSLRequestを受け付けるかどうか、接続してきたポートのSSL/TLS対応状態(0:非対応、1:SSL/TLS対応)を設定
	client_watcher->ssl_support = server_watcher->ssl_support;

	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_client_tailq, client_watcher, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(client fd=%d): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// クライアント別設定用構造体ポインタのI/O監視オブジェクトに対して、コールバック処理とソケットファイルディスクリプタ、そしてイベントのタイプを設定する
	// ----------------
	ev_io_init(&client_watcher->io_watcher, CB_recv, client_watcher->socket_fd, EV_READ);
	ev_io_start(loop, &client_watcher->io_watcher);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_init(CB_recv, client fd=%d, EV_READ): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_start(): OK. Priority=%d\n", __func__, ev_priority(&client_watcher->io_watcher));
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Client %s Connected.\n", client_watcher->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return;
}

// --------------------------------
// IPv4ソケットアクセプト(accept : ソケットに対して接続があったときに発生するイベント)のコールバック処理
// --------------------------------
static void CB_accept_ipv4(struct ev_loop* loop, struct EVS_ev_server_t * server_watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	int                             nonblocking_flag = 0;                                   // ノンブロッキング設定(0:非対応、1:対応))

	struct sockaddr_in              client_sockaddr_in;                                     // IPv4ソケットアドレス
	socklen_t                       client_sockaddr_len = sizeof(client_sockaddr_in);       // IPv4ソケットアドレス構造体のサイズ (バイト単位)
	struct EVS_ev_client_t          *client_watcher = NULL;                                 // クライアント別設定用構造体ポインタ

	// ----------------
	// ソケットアクセプト(accept : リッスンポートに接続があった)
	// ----------------
	socket_result = accept(server_watcher->socket_fd, (struct sockaddr *)&client_sockaddr_in, &client_sockaddr_len);
	// アクセプトしたソケットのディスクリプタがエラーだったら
	if (socket_result < 0)
	{
		// ここでもソケットをクローズをしたほうがいいかな？それともソケットを再設定したほうがいいかな？
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot socket accepting? Total=%d, errno=%d (%s)\n", __func__, server_watcher->socket_fd, EVS_connect_num, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}
	// クライアント接続数を設定
	EVS_connect_num ++;
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): OK. client fd=%d, Total=%d\n", __func__, server_watcher->socket_fd, socket_result, EVS_connect_num);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// クライアント別設定用構造体ポインタのメモリ領域を確保
	client_watcher = (struct EVS_ev_client_t *)calloc(1, sizeof(struct EVS_ev_client_t));
	// メモリ領域が確保できなかったら
	if (client_watcher == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot calloc client_watcher's memory? errno=%d (%s)\n", __func__, server_watcher->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	// クライアント別設定用構造体ポインタにアクセプトしたソケットの情報を設定
	client_watcher->socket_fd = socket_result;                                                                      // ディスクリプタを設定する
	getpeername(client_watcher->socket_fd, (struct sockaddr *)&client_sockaddr_in, &client_sockaddr_len);           // クライアントのアドレス情報を取得しなおす(し直さないと、IPv6でのローカル接続時に惑わされることになるョ。IPv4ではしなくてもいい気もするが…)

	// クライアントのアドレスを文字列として格納
	inet_ntop(PF_INET, (void *)&client_sockaddr_in.sin_addr, client_watcher->addr_str, sizeof(client_watcher->addr_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): inet_ntop(PF_INET): Client address=%s\n", __func__, client_watcher->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));


	// PostgreSQLプロトコルの場合には、STARTTLS的な感じで、平文から暗号化通信になるので、ここまではまだ何かをすることはない


	// ----------------
	// クライアントとの接続ソケットのノンブロッキングモードをnonblocking_flagに設定する
	// ----------------
	socket_result = ioctl(client_watcher->socket_fd, FIONBIO, &nonblocking_flag);
	// 設定ができなかったら
	if (socket_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): ioctl(): Cannot set Non-Blocking mode!? errno=%d (%s)\n", __func__, client_watcher->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(client_watcher);
		return;
	}

	// ----------------
	// 無通信タイムアウトチェックをする(=1:有効)なら
	// ----------------
	if (EVS_config.nocommunication_check == 1)
	{
		ev_now_update(loop);                                                // イベントループの日時を現在の日時に更新
		client_watcher->last_activity = ev_now(loop);                       // 最終アクティブ日時(監視対象が最後にアクティブとなった日時)を設定する
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): last_activity=%.0f\n", __func__, client_watcher->socket_fd, client_watcher->last_activity);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}

	// --------------------------------
	// API関連
	// --------------------------------
	// クライアント毎の状態を、0:接続待ちに設定
	client_watcher->client_status = 0;
	// クライアントからのSSLRequestを受け付けるかどうか、接続してきたポートのSSL/TLS対応状態(0:非対応、1:SSL/TLS対応)を設定
	client_watcher->ssl_support = server_watcher->ssl_support;

	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_client_tailq, client_watcher, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(client fd=%d): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// クライアント別設定用構造体ポインタのI/O監視オブジェクトに対して、コールバック処理とソケットファイルディスクリプタ、そしてイベントのタイプを設定する
	// ----------------
	ev_io_init(&client_watcher->io_watcher, CB_recv, client_watcher->socket_fd, EV_READ);
	ev_io_start(loop, &client_watcher->io_watcher);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_init(CB_recv, client fd=%d, EV_READ): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_start(): OK. Priority=%d\n", __func__, ev_priority(&client_watcher->io_watcher));
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Client %s Connected.\n", client_watcher->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return;
}

// --------------------------------
// UNIXドメインソケットアクセプト(accept : ソケットに対して接続があったときに発生するイベント)のコールバック処理
// --------------------------------
static void CB_accept_unix(struct ev_loop* loop, struct EVS_ev_server_t * server_watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	struct sockaddr_un              client_sockaddr_un;                                     // UNIXドメインソケットアドレス
	socklen_t                       client_sockaddr_len = sizeof(client_sockaddr_un);       // UNIXドメインソケットアドレス構造体のサイズ (バイト単位)
	struct EVS_ev_client_t          *client_watcher;                                        // クライアント別設定用構造体ポインタ

	// ----------------
	// ソケットアクセプト(accept : リッスンポートに接続があった)
	// ----------------
	socket_result = accept(server_watcher->socket_fd, (struct sockaddr *)&client_sockaddr_un, &client_sockaddr_len);
	// アクセプトしたソケットのディスクリプタがエラーだったら
	if (socket_result < 0)
	{
		// ここでもソケットをクローズをしたほうがいいかな？それともソケットを再設定したほうがいいかな？
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot socket accepting? Total=%d, errno=%d (%s)\n", __func__, server_watcher->socket_fd, EVS_connect_num, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}
	// クライアント接続数を設定
	EVS_connect_num ++;
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): OK. client fd=%d, Total=%d\n", __func__, server_watcher->socket_fd, socket_result, EVS_connect_num);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// クライアント別設定用構造体ポインタのメモリ領域を確保
	client_watcher = (struct EVS_ev_client_t *)calloc(1, sizeof(struct EVS_ev_client_t));
	// メモリ領域が確保できなかったら
	if (client_watcher == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot calloc client_watcher's memory? errno=%d (%s)\n", __func__, server_watcher->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return;
	}

	// クライアント別設定用構造体ポインタにアクセプトしたソケットの情報を設定
	client_watcher->socket_fd = socket_result;                                                                  // ディスクリプタを設定する

	// アドレスを文字列として格納
	strcpy(client_watcher->addr_str, "UNIX DOMAIN SOCKET");
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): inet_ntop(PF_UNIX): Client address=%s\n", __func__, client_watcher->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// 無通信タイムアウトチェックをする(=1:有効)なら
	// ----------------
	if (EVS_config.nocommunication_check == 1)
	{
		ev_now_update(loop);                                                // イベントループの日時を現在の日時に更新
		client_watcher->last_activity = ev_now(loop);                       // 最終アクティブ日時(監視対象が最後にアクティブとなった=タイマー更新した日時)を設定する
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): last_activity=%.0f\n", __func__, client_watcher->socket_fd, client_watcher->last_activity);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}

	// --------------------------------
	// API関連
	// --------------------------------
	// クライアント毎の状態を、0:接続待ちに設定
	client_watcher->client_status = 0;
	// クライアントからのSSLRequestを受け付けるかどうか、接続してきたポートのSSL/TLS対応状態(0:非対応、1:SSL/TLS対応)を設定
	client_watcher->ssl_support = server_watcher->ssl_support;

	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_client_tailq, client_watcher, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(client fd=%d): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// クライアント別設定用構造体ポインタのI/O監視オブジェクトに対して、コールバック処理とソケットファイルディスクリプタ、そしてイベントのタイプを設定する
	// ----------------
	ev_io_init(&client_watcher->io_watcher, CB_recv, client_watcher->socket_fd, EV_READ);
	ev_io_start(loop, &client_watcher->io_watcher);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_init(CB_recv, client fd=%d, EV_READ): OK.\n", __func__, client_watcher->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_start(): OK. Priority=%d\n", __func__, ev_priority(&client_watcher->io_watcher));
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Client %s Connected.\n", client_watcher->addr_str);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return;
}

// --------------------------------
// ソケットアクセプト(accept : ソケットに対して接続があったときに発生するイベント)のコールバック処理
// --------------------------------
static void CB_accept(struct ev_loop* loop, struct ev_io *watcher, int revents)
{
	struct EVS_ev_server_t          *server_watcher = (struct EVS_ev_server_t *)watcher;          // サーバー別設定用構造体ポインタ
	char                            log_str[MAX_LOG_LENGTH];

	// イベントにエラーフラグが含まれていたら
	if (EV_ERROR & revents)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Invalid event!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		// 戻る
		return;
	}

	// --------------------------------
	// プロトコルファミリー別に各種初期化処理
	// --------------------------------
	// 該当ソケットのプロトコルファミリーがPF_INET6(=IPv6でのアクセス)なら
	if (server_watcher->socket_address.sa_ipv6.sin6_family == PF_INET6)
	{
		// ----------------
		// IPv6ソケットの初期化
		// ----------------
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): CB_accept_ipv6(): Go!\n", __func__);              // 呼ぶ前にログを出力
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		CB_accept_ipv6(loop, server_watcher, revents);                          // IPv6ソケットのアクセプト処理

		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		// 戻る
		return;
	}
	// 該当ソケットのプロトコルファミリーがPF_INET(=IPv4でのアクセス)なら
	if (server_watcher->socket_address.sa_ipv4.sin_family == PF_INET)
	{
		// ----------------
		// IPv4ソケットの初期化
		// ----------------
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): CB_accept_ipv4(): Go!\n", __func__);              // 呼ぶ前にログを出力
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		CB_accept_ipv4(loop, server_watcher, revents);                          // IPv4ソケットのアクセプト処理

		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		// 戻る
		return;
	} 
	// 該当ソケットのプロトコルファミリーがPF_UNIX(=UNIXドメインソケットなら
	if (server_watcher->socket_address.sa_un.sun_family == PF_UNIX)
	{
		// ----------------
		// UNIXドメインソケットの初期化
		// ----------------
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): CB_accept_unix(): Go!\n", __func__);              // 呼ぶ前にログを出力
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		CB_accept_unix(loop, server_watcher, revents);                          // UNIXドメインソケットのアクセプト処理

		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		// 戻る
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot support protocol family!? 2\n", __func__);
	logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));

	// アイドルイベント開始(メッセージ用キュー処理)
	ev_idle_start(loop, &idle_message_watcher);
	// 戻る
	return;
}
