// ----------------------------------------------------------------------
// Protocol Analyzer for PostgreSQL -
// Purpose:
//     Various API processing.
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
// PostgreSQL処理
// 
// 第52章 フロントエンド/バックエンドプロトコル                                   https://www.postgresql.jp/document/12/html/protocol.html
//      52.2. メッセージの流れ                                                  https://www.postgresql.jp/document/12/html/protocol-flow.html
//      52.7. メッセージの書式                                                  https://www.postgresql.jp/document/12/html/protocol-message-formats.html
// 
// この辺を読んどけば判るかな？
// --------------------------------
// --------------------------------
// クライアント送信処理 ※(PostgreSQL→クライアントは、そのままでは送らない)
// --------------------------------
int API_pgsql_client_send(struct EVS_ev_client_t *this_client, unsigned char *message_ptr, int message_len)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	// ----------------
	// 非SSL通信(=0)なら
	// ----------------
	if (this_client->ssl_status == 0)
	{
		// ----------------
		// ソケット送信(send : ソケットのファイルディスクリプタに対して、msg_bufからmsg_lenのメッセージを送信する。(ノンブロッキングにするなら0ではなくてMSG_DONTWAIT)
		// ----------------
		api_result = send(this_client->socket_fd, (void*)message_ptr, message_len, 0);
		// 送信したバイト数が負(<0)だったら(エラーです)
		if (api_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): send(): Cannot send message? errno=%d (%s)\n", __func__, this_client->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return api_result;
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): send(): OK. length=%d\n", __func__, this_client->socket_fd, message_len);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}
	// ----------------
	// SSLハンドシェイク中なら
	// ----------------
	else if (this_client->ssl_status == 1)
	{
		// ERROR!?!? (TBD)
	}
	// ----------------
	// SSL接続中なら
	// ----------------
	else if (this_client->ssl_status == 2)
	{
		// ----------------
		// OpenSSL(SSL_write : SSLデータ書き込み)
		// ----------------
		api_result = SSL_write(this_client->ssl, (void*)message_ptr, message_len);
		// 送信したバイト数が負(<0)だったら(エラーです)
		if (api_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL_write(): Cannot write encrypted message!?\n", __func__, this_client->socket_fd, ERR_reason_error_string(ERR_get_error()));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return api_result;
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSL_write(): OK. length=%d\n", __func__, this_client->socket_fd, message_len);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}
	// 戻る
	return 0;
}

// --------------------------------
// クライアントからの開始メッセージの各種設定値を解析してparam_bufにコピーするとともに、param_infoにそのポインタを設定する)
// --------------------------------
int API_pgsql_client_decodestartmessage(char *param_ptr, int param_len, char *param_buf, char *param_info[])
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	int                             param_nun = 0;

	char                            separator_data[] = {'\0'};
	
	struct EVS_value_t              result_list[10];                    // 設定値とその長さの構造体
	int                             list_num;

	// 各種設定値バッファがNULLだったり、長さが無ければ
	if (param_ptr == NULL || param_len <= 0)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): param_ptr is NULL!? (param_len=%d)\n", __func__, param_len);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// データ分割処理で、各種設定値をセパレータ(\0)で分離する(最大10個まで)
	api_result = memmemlist(param_ptr, param_len, separator_data, sizeof(separator_data), sizeof(result_list), result_list);

	// 各種設定値の中から、必要なものを格納する
	for (list_num = 0; list_num < api_result; list_num += 2)
	{
		// 設定値名があるなら
		if (result_list[list_num].value_ptr && result_list[list_num].value_len)
		{
			// ----------------
			// クライアントからの開始メッセージの各種設定値をスキャンして、該当する設定値名があれば、それをparam_bufにコピーするとともに、param_infoにそのポインタを設定する
			// ----------------
			for (param_nun = 0; param_nun < CLIENT_PARAM_END; param_nun++)
			{
				// 対象変数名が設定値名と合致すれば
				if (strncasecmp(result_list[list_num].value_ptr, PgSQL_client_param_list[param_nun], result_list[list_num].value_len) == 0)
				{
					// 設定値を各種設定値用バッファにコピー
					param_info[param_nun] = strncpy(param_buf, result_list[list_num + 1].value_ptr, result_list[list_num + 1].value_len);
					// 各種設定値用バッファポインタをずらす
					param_buf += strlen(param_info[param_nun]) + 1;
					snprintf(log_str, MAX_LOG_LENGTH, "%s(): StartupMessage %s=%s\n", __func__, PgSQL_client_param_list[param_nun], param_info[param_nun]);
					logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
					// for()を抜ける
					break;
				}
			}
			// PgSQL_client_param_list[]に予め定義されている設定値名がない場合には
			if (param_nun == CLIENT_PARAM_END)
			{
				snprintf(log_str, MAX_LOG_LENGTH, "%s(): StartupMessage %s=%s\n", __func__, result_list[list_num].value_ptr, result_list[list_num + 1].value_ptr);
				logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			}
		}
	}

	// 戻る
	return api_result;
}

// --------------------------------
// クライアントクエリメッセージ解析処理
// --------------------------------
int API_pgsql_client_message(struct EVS_ev_message_t *message_info)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	char                            *message_ptr = message_info->message_ptr;

	unsigned char                   message_type = 0;
	unsigned int                    message_len = 0;

	unsigned char                   *target_ptr;

	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): START! message_len=%d, client_status=%d\n", __func__, message_info->client_socket_fd, message_info->message_len, message_info->client_status);
	logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));

	// ダンプ出力
	dump2log(LOG_DIRECT, LOGLEVEL_DUMP, &(message_info->message_tv), (void *)message_info->message_ptr, message_info->message_len & 0x3FF);

	// ------------------------------------
	// ★ここでクライアント側から来たクエリ(簡易問い合わせ)の解析をすべきか？
	// ------------------------------------
	// メッセージタイプを取得
	message_type = message_ptr[0];
	// メッセージ長を取得(int32)
	target_ptr = (unsigned char *)&message_len;
	*target_ptr =  message_ptr[4];
	target_ptr ++;
	*target_ptr =  message_ptr[3];
	target_ptr ++;
	*target_ptr =  message_ptr[2];
	target_ptr ++;
	*target_ptr =  message_ptr[1];

	// メッセージタイプ別処理分岐
	switch (message_type)
	{
		case 'Q':                                               // 0x51 : Q ... 簡易問い合わせ(F)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "Client %s -> %s. (message size=%d, len=0x%02x, data:\"%s\")\n", message_info->client_addr_str, PgSQL_message_front_str[message_type], 1 + message_len, message_len, message_ptr + 5);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		case 'X':                                               // 0x58 : X ... 終了(F)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "Client %s -> %s. (message size=%d, len=0x%02x)\n", message_info->client_addr_str, PgSQL_message_front_str[message_type], 1 + message_len, message_len);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		default:
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Type:%s, Message size=%d Length=%0d, Data=%s Value:...\n", __func__, message_info->client_socket_fd, PgSQL_message_front_str[message_type], 1 + message_len, message_len, message_ptr + 5);
			logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
	}

	// 戻る
	return api_result;
}

// --------------------------------
// クライアントクエリ処理
// --------------------------------
int API_pgsql_client_query(struct EVS_ev_client_t *this_client)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = this_client->pgsql_info;
	struct EVS_db_t                 *db_info = (struct EVS_db_t *)this_pgsql->db_info;

	char                            *message_ptr = this_client->recv_buf;
	unsigned int                    message_len = 0;

	// ------------------------------------
	// クエリキューイング処理　※メッセージをその都度解析していたら遅くなるので、いったん接続状態になったら、メッセージをキューに入れて後で解析する
	// ------------------------------------
	struct EVS_ev_message_t         *message_info;                      // メッセージ用構造体ポインタ

	// メッセージ用構造体ポインタのメモリ領域を確保
	message_info = (struct EVS_ev_message_t *)calloc(1, sizeof(struct EVS_ev_message_t));
	// メモリ領域が確保できなかったら
	if (message_info == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot calloc message_info's memory? errno=%d (%s)\n", __func__, this_client->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// メッセージ情報にメッセージの各種情報をコピー
	message_info->from_to = 101;                                        // メッセージの方向
	message_info->client_socket_fd = this_client->socket_fd;            // 接続してきたクライアントのファイルディスクリプタ
	message_info->client_status = this_client->client_status;           // クライアント毎の状態
	message_info->client_ssl_status = this_client->ssl_status;          // クライアント毎のSSL接続状態
	strcpy(message_info->client_addr_str, this_client->addr_str);       // クライアントのアドレス文字列

	message_info->pgsql_socket_fd = this_pgsql->socket_fd;              // 接続したPostgreSQLのファイルディスクリプタ
	message_info->pgsql_status = this_pgsql->pgsql_status;              // PostgreSQL毎の状態
	message_info->pgsql_ssl_status = this_pgsql->ssl_status;            // PostgreSQL毎のSSL接続状態
	strcpy(message_info->pgsql_addr_str, this_pgsql->addr_str);         // PostgreSQLのアドレス文字列

	gettimeofday(&message_info->message_tv, NULL);                      // 現在時刻を取得してmessage_info->message_tvに格納

	// 受信したデータ分だけメモリ確保
	message_info->message_ptr = malloc(this_client->recv_len);
	// メモリ領域が確保できなかったら
	if (message_info->message_ptr == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot calloc message_info->message_ptr's memory? errno=%d (%s)\n", __func__, this_client->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}
	// 受信したデータをコピー
	memcpy(message_info->message_ptr, this_client->recv_buf, this_client->recv_len);
	message_info->message_len = this_client->recv_len;

	// --------------------------------
	// テールキュー処理
	// --------------------------------
	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_message_tailq, message_info, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(message): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// クライアントから送られてきたクエリメッセージを、そのまま接続先のPostgreSQLに対して送信する
	api_result = API_pgsql_server_send(this_pgsql, this_client->recv_buf, this_client->recv_len);

	// 戻る
	return api_result;
}

// --------------------------------
// クライアント開始メッセージ解析処理
// --------------------------------
int API_pgsql_client_start(struct EVS_ev_client_t *this_client)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	unsigned int                    message_len = 0;
	unsigned short int              major_version_num = 0;
	unsigned short int              minor_version_num = 0;

	char                            *target_ptr;

	const char                      *ssl_ok_message[] = {"N", "S"};

	// ダンプ出力
	dump2log(LOG_QUEUEING, LOGLEVEL_DUMP, NULL, (void *)this_client->recv_buf, this_client->recv_len & 0x3FF);

	// 最初の4バイトからメッセージ長を取得
	target_ptr = (char *)&message_len;
	*target_ptr =  this_client->recv_buf[3];
	target_ptr ++;
	*target_ptr =  this_client->recv_buf[2];
	target_ptr ++;
	*target_ptr =  this_client->recv_buf[1];
	target_ptr ++;
	*target_ptr =  this_client->recv_buf[0];

	// 受信メッセージの長さが、メッセージ長と異なるなら
	if (message_len != this_client->recv_len)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): StartupMessage length ERROR!? (message_len=%0d != recv_len=%0d)\n", __func__, this_client->socket_fd, message_len, this_client->recv_len);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		// 戻る
		return -1;
	}
	// 上記以外は少なくとも開始メッセージとして処理すべき

	// メッセージ長が0x00000008なら、そのあとの4バイトが固定値(0x04, 0xd2, 0x16, 0x2f(= 1234, 5678))なら、SSL接続リクエスト。それ以外は通常の開始メッセージ(のはず)
	if (message_len == 0x08)
	{
		// あとに続く4バイトが固定値(0x04, 0xd2, 0x16, 0x2f(= 1234, 5678))なら、SSL接続リクエスト
		if (this_client->recv_buf[4] == (char)0x04 &&
			this_client->recv_buf[5] == (char)0xd2 &&
			this_client->recv_buf[6] == (char)0x16 &&
			this_client->recv_buf[7] == (char)0x2f)
		{
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "Client %s -> SSLRequest. (message size=%d, len=0x%02x)\n", this_client->addr_str, message_len, message_len);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

			// ここで"SSLOK"を送信
			// ----------------
			// ソケット送信(send : クライアント側からのSSLRequestに対して、ポート別にSSL/TLS通信の可(S)/不可(N)を送信する。(ノンブロッキングにするなら0ではなくてMSG_DONTWAIT)
			// ----------------
			api_result = send(this_client->socket_fd, (void*)ssl_ok_message[this_client->ssl_support], 1, 0);
			// 送信したバイト数が負(<0)だったら(エラーです)
			if (api_result < 0)
			{
				snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): send(): Cannot send message? errno=%d (%s)\n", __func__, this_client->socket_fd, errno, strerror(errno));
				logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
				return api_result;
			}

			// ダンプ出力(メッセージタイプの1+を忘れずに)
			dump2log(LOG_QUEUEING, LOGLEVEL_DUMP, NULL, (void *)ssl_ok_message[this_client->ssl_support], 1);

			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): send(%s): OK.\n", __func__, this_client->socket_fd, ssl_ok_message[this_client->ssl_support]);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

			// クライアントが接続してきたポートがSSLに対応しているなら
			if (this_client->ssl_support == 1)
			{
				// --------------------------------
				// SSL接続情報生成＆ファイルディスクリプタ紐づけ
				// --------------------------------
				CB_accept_SSL(this_client);
				snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): this_client->ssl_status %d -> 1!!\n", __func__, this_client->socket_fd, this_client->ssl_status);
				logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
				// SSLハンドシェイク前(=1)に設定
				this_client->ssl_status = 1;
				// 標準ログに出力
				snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> Client(%s), SSL supported (message size=1 len=0x01)\n", this_client->addr_str);
				logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
				// 戻る(SSLハンドシェイク開始)
				return 0;
			}
			else
			{
				// 標準ログに出力
				snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> Client(%s), No SSL support (message size=1 len=0x01)\n", this_client->addr_str);
				logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
				// 戻る(通常のStartupMessageを待つ)
				return 0;
			}       
		}
		// それ以外は
		else
		{
			// エラー
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): SSLRequest ERROR!?\n", __func__, this_client->socket_fd);
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// 戻る
			return -1;    
		}
	}
	// それ以外は通常の開始メッセージ(のはず)
	else
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): this_client->client_status %d -> 1!!\n", __func__, this_client->socket_fd, this_client->client_status);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		// クライアント毎の状態を、1:開始メッセージ応答待ちに設定
		this_client->client_status = 1;
		// 標準ログに出力
		snprintf(log_str, MAX_LOG_LENGTH, "Client %s -> StartupMessage. (message size=%d, len=0x%02x)\n", this_client->addr_str, message_len, message_len);
		logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
	}

	// メジャーバージョンとマイナーバージョンを取得
	target_ptr = (unsigned char *)&major_version_num;
	*target_ptr =  this_client->recv_buf[5];
	target_ptr ++;
	*target_ptr =  this_client->recv_buf[4];

	target_ptr = (unsigned char *)&minor_version_num;
	*target_ptr =  this_client->recv_buf[7];
	target_ptr ++;
	*target_ptr =  this_client->recv_buf[6];

	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): major_version_num=0x%02hx(=%0d), minor_version_num=0x%02hx(=%0d)\n", __func__, this_client->socket_fd, major_version_num, major_version_num, minor_version_num, minor_version_num);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// その他、各種パラメータ取得して、接続してきたユーザー名と接続先のDB名を取得すること。
	// これらが判れば、どこのサーバーにアクセスすればいいかは設定から判るはず。
	// その他のオプションについてはここでは気にしないほうがいいかな？(application_nameとかclient_encodingとか)

	// クライアントからの開始メッセージの各種設定値を解析してparam_bufにコピーするとともに、param_infoにそのポインタを設定する)
	API_pgsql_client_decodestartmessage(this_client->recv_buf + 8, this_client->recv_len - 8, this_client->param_buf, this_client->param_info);
	// クライアントから送られてきた開始メッセージに基づいて、予め設定ファイルで指定されたPostgreSQLに対して接続を開始する(クエリ以外は来ないはず)
	api_result = API_pgsql_server_start(this_client);
	// 正常終了でないなら
	if (api_result != 0)
	{
		// 戻る
		return api_result;
	}

	// PgAnalyzer自身がPostgreSQLとの接続を確立するまでは、クライアントからのメッセージは送ってはならない

	// 戻る
	return api_result;
}
