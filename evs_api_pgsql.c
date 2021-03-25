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
// --------------------------------------------------------------------------------------------------------------------------------
// ↓PostgreSQLからの受信関係
// --------------------------------------------------------------------------------------------------------------------------------
// PostgreSQLからのレスポンスメッセージは、以下のようにまとめて来る…場合もあるョ
// 
// 52 00 00 00 08 00 00 00  00 53 00 00 00 1a 61 70    R....... .S....ap
// 70 6c 69 63 61 74 69 6f  6e 5f 6e 61 6d 65 00 70    plicatio n_name.p
// 73 71 6c 00 53 00 00 00  19 63 6c 69 65 6e 74 5f    sql.S... .client_
// 65 6e 63 6f 64 69 6e 67  00 55 54 46 38 00 53 00    encoding .UTF8.S.
// 00 00 17 44 61 74 65 53  74 79 6c 65 00 49 53 4f    ...DateS tyle.ISO
// 2c 20 4d 44 59 00 53 00  00 00 19 69 6e 74 65 67    , MDY.S. ...integ
// 65 72 5f 64 61 74 65 74  69 6d 65 73 00 6f 6e 00    er_datet imes.on.
// 53 00 00 00 1b 49 6e 74  65 72 76 61 6c 53 74 79    S....Int ervalSty
// 6c 65 00 70 6f 73 74 67  72 65 73 00 53 00 00 00    le.postg res.S...
// 15 69 73 5f 73 75 70 65  72 75 73 65 72 00 6f 66    .is_supe ruser.of
// 66 00 53 00 00 00 19 73  65 72 76 65 72 5f 65 6e    f.S....s erver_en
// 63 6f 64 69 6e 67 00 55  54 46 38 00 53 00 00 00    coding.U TF8.S...
// 18 73 65 72 76 65 72 5f  76 65 72 73 69 6f 6e 00    .server_ version.
// 31 32 2e 34 00 53 00 00  00 23 73 65 73 73 69 6f    12.4.S.. .#sessio
// 6e 5f 61 75 74 68 6f 72  69 7a 61 74 69 6f ....
// 
// なので、バッファポインタを駆使して、メッセージ毎に処理をしないといけない

// --------------------------------
// PostgreSQL側各種クエリレスポンス解析処理 ※透過モード時に溜め込んだメッセージを解析してログに出力する
// --------------------------------
int API_pgsql_message_decodequeryresponse(struct EVS_ev_message_t *message_info, char *message_ptr, unsigned int message_len)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	unsigned char                   message_type = message_ptr[0];

	unsigned char                   *target_ptr;

	// ------------------------------------
	// ★ここで、PostgreSQLから来たメッセージ別に、現在のクライアントの状態(client_status)等を変更しないといけないョ!!
	// ------------------------------------
	unsigned int                    auth_type;
	unsigned short                  field_num;
	unsigned short                  column_num;
	unsigned int                    column_len;
	unsigned int                    backend_pid;
	unsigned int                    backend_key;

	char                            *name_ptr = message_ptr + 5;        // 設定値名ポインタ
	int                             name_len = 0;                       // 設定値名の長さ

	char                            *value_ptr = NULL;                  // 設定値ポインタ
	int                             value_len = 0;                      // 設定値の長さ

	// ダンプ出力
	dump2log(LOG_DIRECT, LOGLEVEL_DUMP, &(message_info->message_tv), (void *)message_ptr, (1 + message_len) & 0x3FF);

	// メッセージタイプ別処理分岐
	switch (message_type)
	{
		case 'C':                                                       // 0x43 : C ... コマンド完了(B)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, data=%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr + 5);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		case 'D':                                                       // 0x44 : D ... データ行(B)
			// 列値を取得(int16)
			target_ptr = (unsigned char *)&column_num;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// メッセージ長を取得(int32)
			target_ptr = (unsigned char *)&column_len;
			*target_ptr =  message_ptr[10];
			target_ptr ++;
			*target_ptr =  message_ptr[9];
			target_ptr ++;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, column_num:%d, 1st_column_len:%d)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, column_num, column_len);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		case 'E':                                                       // 0x45 : E ... エラー(B)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, 1st-field:%c, 1st-value:%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr[5], message_ptr + 6);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		case 'K':                                                       // 0x4B : K ... 取り消しする際のキーデータ(B)
			// バックエンドのプロセスIDを取得(int32)
			target_ptr = (unsigned char *)&backend_pid;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			target_ptr ++;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// バックエンドの秘密鍵を取得(int32)
			target_ptr = (unsigned char *)&backend_key;
			*target_ptr =  message_ptr[12];
			target_ptr ++;
			*target_ptr =  message_ptr[11];
			target_ptr ++;
			*target_ptr =  message_ptr[10];
			target_ptr ++;
			*target_ptr =  message_ptr[9];
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, backend_pid:%d, backend_key:0x%08x)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, backend_pid, backend_key);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		case 'R':                                                       // 0x52 : R ... OKか、特定の認証が必要かはメッセージ内容による(B)
			// 認証方式を取得(int32)
			target_ptr = (unsigned char *)&auth_type;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			target_ptr ++;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// 認証方式別処理分岐
			switch (auth_type)
			{
				case 0:                                                 // AuthenticationOk ※PosgreSQLと2:接続中(pgsql_status==2)になったら、こっちに処理が来るようにする
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): client_status %d -> 2!\n", __func__, message_info->pgsql_socket_fd, message_info->client_status);
					logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
					// 標準ログに出力
					snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> AuthenticationOk. (message size=%d, len=0x%02x)\n", 1 + message_len, message_len);
					logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
					break;
				default:
					// エラー
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal Authentication Response!? (client_status=%d, auth_type=%d)\n", __func__, message_info->pgsql_socket_fd, message_info->client_status, auth_type);
					logging(LOG_DIRECT, LOGLEVEL_ERROR, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
					// 戻る
					return -1;
					break;
			}
			break;
		case 'S':                                                       // 0x53 : S ... 実行時パラメータ状態報告(B)
			// 設定値名の長さを取得
			name_len = strlen(name_ptr);
			// 設定値の長さが各種設定値の全体長よりも長いなら\0が見つからない？等おかしいので
			if (name_ptr + name_len + 1 > message_ptr + 5 + message_len)
			{
				// エラー
				snprintf(log_str, MAX_LOG_LENGTH, "%s(): name_ptr + name_len + 1 > message_ptr + 5 + message_len!?\n", __func__);
				logging(LOG_DIRECT, LOGLEVEL_ERROR, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
				return -1;
			}
			// 設定値ポインタを設定値名の次(\0の次なので+1)に移動する
			value_ptr = name_ptr + name_len + 1;
			// 設定値の長さを取得
			value_len = strlen(value_ptr);
			// 設定値の長さが各種設定値の全体長よりも長いなら\0が見つからない？等おかしいので
			if (value_ptr + value_len + 1 > message_ptr + 5 + message_len)
			{
				// エラー
				snprintf(log_str, MAX_LOG_LENGTH, "%s(): value_ptr + value_len + 1 > message_ptr + 5 + message_len!?\n", __func__);
				logging(LOG_DIRECT, LOGLEVEL_ERROR, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
				return -1;
			}
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, %s=%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, name_ptr, value_ptr);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'T':                                                       // 0x54 : T ... 行の記述(B)
			// 行のフィールド数を取得(int16)
			target_ptr = (unsigned char *)&field_num;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, field_num:%d)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, field_num);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		case 'Z':                                                       // 0x5A : Z ... 新しい問い合わせサイクルの準備が整った
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->pgsql_status %d -> 10!!\n", __func__, message_info->pgsql_socket_fd, message_info->pgsql_status);
			logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, Transaction:%c)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr[5]);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
		default:
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): Type:%s Length:%0d Data:%s Value:...\n", __func__, PgSQL_message_backend_str[message_type], message_len, message_ptr + 5);
			logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			break;
	}

	// PostgreSQLから送られてきたクエリメッセージを、クライアントに対して送信する(PostgreSQL→クライアントは、そのままでは送らない)
////    api_result = API_pgsql_client_send(this_client, message_ptr, 1 + message_len);

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> Client(%s) (message size=%d, len=0x%02x)\n", message_info->client_addr_str, 1 + message_len, message_len);
	logging(LOG_DIRECT, LOGLEVEL_LOG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return api_result;
}

// --------------------------------
// PostgreSQL側各種クエリレスポンス解析処理
// --------------------------------
int API_pgsql_server_decodequeryresponse(struct EVS_ev_pgsql_t *this_pgsql, char *message_ptr, unsigned int message_len)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;

	unsigned char                   message_type = message_ptr[0];
	unsigned char                   *target_ptr;

	// ------------------------------------
	// ★ここで、PostgreSQLから来たメッセージ別に、現在のクライアントの状態(client_status)等を変更しないといけないョ!!
	// ------------------------------------
	unsigned int                    auth_type;
	unsigned short                  field_num;
	unsigned short                  column_num;
	unsigned int                    column_len;
	unsigned int                    backend_pid;
	unsigned int                    backend_key;

	char                            *name_ptr = message_ptr + 5;        // 設定値名ポインタ
	int                             name_len = 0;                       // 設定値名の長さ

	char                            *value_ptr = NULL;                  // 設定値ポインタ
	int                             value_len = 0;                      // 設定値の長さ

	// ダンプ出力
	dump2log(LOG_QUEUEING, LOGLEVEL_DUMP, NULL, (void *)message_ptr, (1 + message_len) & 0x3FF);

	// メッセージタイプ別処理分岐
	switch (message_type)
	{
		case 'C':                                                       // 0x43 : C ... コマンド完了(B)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, data=%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr + 5);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'D':                                                       // 0x44 : D ... データ行(B)
			// 列値を取得(int16)
			target_ptr = (unsigned char *)&column_num;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// メッセージ長を取得(int32)
			target_ptr = (unsigned char *)&column_len;
			*target_ptr =  message_ptr[10];
			target_ptr ++;
			*target_ptr =  message_ptr[9];
			target_ptr ++;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, column_num:%d, 1st_column_len:%d)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, column_num, column_len);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'E':                                                       // 0x45 : E ... エラー(B)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, 1st-field:%c, 1st-value:%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr[5], message_ptr + 6);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'K':                                                       // 0x4B : K ... 取り消しする際のキーデータ(B)
			// バックエンドのプロセスIDを取得(int32)
			target_ptr = (unsigned char *)&backend_pid;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			target_ptr ++;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// バックエンドの秘密鍵を取得(int32)
			target_ptr = (unsigned char *)&backend_key;
			*target_ptr =  message_ptr[12];
			target_ptr ++;
			*target_ptr =  message_ptr[11];
			target_ptr ++;
			*target_ptr =  message_ptr[10];
			target_ptr ++;
			*target_ptr =  message_ptr[9];
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, backend_pid:%d, backend_key:0x%08x)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, backend_pid, backend_key);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'R':                                                       // 0x52 : R ... OKか、特定の認証が必要かはメッセージ内容による(B)
			// 認証方式を取得(int32)
			target_ptr = (unsigned char *)&auth_type;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			target_ptr ++;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// 認証方式別処理分岐
			switch (auth_type)
			{
				case 0:                                                 // AuthenticationOk ※PosgreSQLと2:接続中(pgsql_status==2)になったら、こっちに処理が来るようにする
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_client->client_status %d -> 2!\n", __func__, this_pgsql->socket_fd, this_client->client_status);
					logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
					// クライアント毎の状態を、2:クエリメッセージ待ちに設定
					this_client->client_status = 2;
					// 標準ログに出力
					snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> AuthenticationOk. (message size=%d, len=0x%02x)\n", 1 + message_len, message_len);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				default:
					// エラー
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal Authentication Response!? (client_status=%d, auth_type=%d)\n", __func__, this_pgsql->socket_fd, this_client->client_status, auth_type);
					logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
					// 戻る
					return -1;
					break;
			}
			break;
		case 'S':                                                       // 0x53 : S ... 実行時パラメータ状態報告(B)
			// 設定値名の長さを取得
			name_len = strlen(name_ptr);
			// 設定値の長さが各種設定値の全体長よりも長いなら\0が見つからない？等おかしいので
			if (name_ptr + name_len + 1 > message_ptr + 5 + message_len)
			{
				// エラー
				snprintf(log_str, MAX_LOG_LENGTH, "%s(): name_ptr + name_len + 1 > message_ptr + 5 + message_len!?\n", __func__);
				logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
				return -1;
			}
			// 設定値ポインタを設定値名の次(\0の次なので+1)に移動する
			value_ptr = name_ptr + name_len + 1;
			// 設定値の長さを取得
			value_len = strlen(value_ptr);
			// 設定値の長さが各種設定値の全体長よりも長いなら\0が見つからない？等おかしいので
			if (value_ptr + value_len + 1 > message_ptr + 5 + message_len)
			{
				// エラー
				snprintf(log_str, MAX_LOG_LENGTH, "%s(): value_ptr + value_len + 1 > message_ptr + 5 + message_len!?\n", __func__);
				logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
				return -1;
			}
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, %s=%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, name_ptr, value_ptr);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'T':                                                       // 0x54 : T ... 行の記述(B)
			// 行のフィールド数を取得(int16)
			target_ptr = (unsigned char *)&field_num;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, field_num:%d)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, field_num);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'Z':                                                       // 0x5A : Z ... 新しい問い合わせサイクルの準備が整った
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->pgsql_status %d -> 10!!\n", __func__, this_pgsql->socket_fd, this_pgsql->pgsql_status);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// PostgreSQLへの接続状態を、10:テストの透過モードに設定
			this_pgsql->pgsql_status = 10;
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, Transaction:%c)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr[5]);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		default:
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): Type:%s Length:%0d Data:%s Value:...\n", __func__, PgSQL_message_backend_str[message_type], message_len, message_ptr + 5);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
	}

	// PostgreSQLから送られてきたクエリメッセージを、クライアントに対して送信する(PostgreSQL→クライアントは、そのままでは送らない)
	api_result = API_pgsql_client_send(this_client, message_ptr, 1 + message_len);

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> Client(%s) (message size=%d, len=0x%02x)\n", this_client->addr_str, 1 + message_len, message_len);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return api_result;
}
			
// --------------------------------
// PostgreSQL側開始メッセージレスポンス解析処理
// --------------------------------
int API_pgsql_server_decodestartresponse(struct EVS_ev_pgsql_t *this_pgsql, char *message_ptr, unsigned int message_len)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;

	unsigned char                   message_type = message_ptr[0];
	unsigned char                   *target_ptr;

	unsigned int                    auth_type;
	unsigned int                    request_minorversion_num;
	unsigned int                    unknown_option_num;
	char                            *option_name;

	// ダンプ出力
	dump2log(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, (void *)this_pgsql->recv_buf, this_pgsql->recv_len & 0x3FF);

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): START! recv_len=%d, message_len=%d, pgsql_status=%d\n", __func__, this_pgsql->socket_fd, this_pgsql->recv_len, message_len, this_pgsql->pgsql_status);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ここではまだPostgreSQLとの接続はできていないので、'S'(SSL OK)か'N'(SSL NO)の一バイトメッセージか、
	// もしくはメッセージタイプが'R'(Authentication)、'E'(ErrorResponse)、'v'(NegotiateProtocolVersion)以外は受け付けない
	// メッセージタイプ別処理分岐
	switch (message_type)
	{
		case 'S':                                                       // PostgreSQLからのレスポンスが'S'(SSL OK)なら
			// PostgreSQLから受信したメッセージの長さは確認できないので、そのまま受け入れるしかない
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->ssl_status %d -> 1!\n", __func__, this_pgsql->socket_fd, this_pgsql->ssl_status);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// SSLハンドシェイク中(=1)に設定
			this_pgsql->ssl_status = 1;
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> SSLRequest ACCEPTED.\n");
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			// PostgreSQL SSLハンドシェイク処理
			api_result =  API_pgsql_SSLHandshake(this_pgsql);
			// 戻る
			return  api_result;
			break;
		case 'N':                                                       // PostgreSQLからのレスポンスが'N'(SSL NO)なら
			// SSL/TLS接続は非対応らしい
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->ssl_status %d -> 0!\n", __func__, this_pgsql->socket_fd, this_pgsql->ssl_status);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// SSL接続状態を、0:非SSLに設定
			this_pgsql->ssl_status = 0;
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> SSLRequest REJECTED.\n");
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			// PostgreSQL StartupMessage送信処理 (※この関数を呼ぶ時には、this_client->param_infoに完璧なデータが入っている前提)
			api_result = API_pgsql_send_StartupMessage(this_pgsql);
			// 戻る
			return api_result;
			break;
		// --------------------------------
		// 上記以外は通常のメッセージフォーマットのはず
		// --------------------------------
		case 'E':                                                       // 0x45 : E ... エラー(B)
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, 1st-field:%c, 1st-value:%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, message_ptr[5], message_ptr + 6);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'v':                                                       // 0x76 : v ... プロトコルバージョン交渉(B)
			// サーバがサポートする最新のマイナープロトコルバージョンを取得(int32)
			target_ptr = (unsigned char *)&request_minorversion_num;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			target_ptr ++;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// サーバが認識しなかったプロトコルオプションの数(int32)
			target_ptr = (unsigned char *)&unknown_option_num;
			*target_ptr =  message_ptr[12];
			target_ptr ++;
			*target_ptr =  message_ptr[11];
			target_ptr ++;
			*target_ptr =  message_ptr[10];
			target_ptr ++;
			*target_ptr =  message_ptr[9];
			// サーバが認識しなかったプロトコルオプション名(\0区切りで複数の可能性あり)
			option_name = message_ptr + 13;
			// 標準ログに出力
			snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> %s. (message size=%d, len=0x%02x, request_minorversion_num:%d, unknown_option_num:%d, 1st-option_name:%s)\n", PgSQL_message_backend_str[message_type], 1 + message_len, message_len, request_minorversion_num, unknown_option_num, option_name);
			logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
			break;
		case 'R':                                                       // 0x52 : R ... OKか、特定の認証が必要かはメッセージ内容による(B)
			// クライアント毎の状態が、1:開始メッセージ応答待ちでないなら
			if (this_pgsql->pgsql_status != 1)
			{
				// エラー
				snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal Authentication Response!? (client_status=%d)\n", __func__, this_pgsql->socket_fd, this_client->client_status);
				logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
				// 戻る
				return -1;
			}
			// 認証方式を取得(int32)
			target_ptr = (unsigned char *)&auth_type;
			*target_ptr =  message_ptr[8];
			target_ptr ++;
			*target_ptr =  message_ptr[7];
			target_ptr ++;
			*target_ptr =  message_ptr[6];
			target_ptr ++;
			*target_ptr =  message_ptr[5];
			// 認証方式別処理分岐
			switch (auth_type)
			{
				case 0:                                                 // AuthenticationOk
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->pgsql_status %d -> 2!!\n", __func__, this_pgsql->socket_fd, this_pgsql->pgsql_status);
					logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
					// PostgreSQLへの接続状態を、2:接続中に設定
					this_pgsql->pgsql_status = 2;
					// AuthenticationOkについては、API_pgsql_server_decodequeryresponse()の方でログに出力するので、ここではログに出力しないことにする
					break;
				case 2:                                                 // AuthenticationKerberosV5 : Kerberos V5認証が必要
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Type:AuthenticationKerberosV5 Length:%0d\n", __func__, this_pgsql->socket_fd, message_len);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				case 3:                                                 // AuthenticationCleartextPassword : 平文パスワードが必要
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Type:AuthenticationCleartextPassword Length:%0d\n", __func__, this_pgsql->socket_fd, message_len);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				case 5:                                                 // AuthenticationMD5Password : MD5暗号化パスワードが必要
					// 標準ログに出力
					snprintf(log_str, MAX_LOG_LENGTH, "PostgreSQL -> AuthenticationMD5Password. (message size=%d, len=0x%02x, salt:0x%0hhx,0x%0hhx,0x%0hhx,0x%0hhx)\n", 1 + message_len, message_len, message_ptr[9], message_ptr[10], message_ptr[11], message_ptr[12]);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					// PostgreSQL PasswordMessage(MD5)処理 (※ソルトキーはthis_pgsql->recv_buf + 9から4バイトで入っている)
					api_result = API_pgsql_send_PasswordMessageMD5(this_pgsql);
					break;
				case 6:                                                 // AuthenticationSCMCredential : SCM資格証明メッセージが必要
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Type:AuthenticationSCMCredential Length:%0d\n", __func__, this_pgsql->socket_fd, message_len);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				case 7:                                                 // AuthenticationGSS : GSSAPI認証証明メッセージが必要
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Type:AuthenticationGSS Length:%0d\n", __func__, this_pgsql->socket_fd, message_len);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				case 8:                                                 // AuthenticationGSSContinue : GSSPAIまたはSSPIデータを含む
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Type:AuthenticationGSSContinue Length:%0d Data:0x%0hx...\n", __func__, this_pgsql->socket_fd, message_len, message_ptr[9]);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				case 9:                                                 // AuthenticationSSPI : SSPI認証証明メッセージが必要
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Type:AuthenticationSSPI Length:%0d Data:%s...\n", __func__, this_pgsql->socket_fd, message_len, message_ptr + 9);
					logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
					break;
				// GitHUB公開版では、SASL認証(sha256認証)については削除する(OpenSSLのBASE64関連が使いづらく、PostgreSQLのソースからBASE64関連含めてコピーしたらできるよ)
				case 10:                                                // AuthenticationSASL : SASL認証が必要
				case 11:                                                // AuthenticationSASLContinue : SASLのチャレンジを含む
				case 12:                                                // AuthenticationSASLFinal : SASL認証が完了
				default:
					// エラー
					snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal Authentication Response!? (auth_type=%d)\n", __func__, this_pgsql->socket_fd, auth_type);
					logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
					// 戻る
					return -1;
					break;
			}
			break;
		default:
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal SSLRequest Response!? Type:%s Length:%0d Data:%s!?\n", __func__, this_pgsql->socket_fd, PgSQL_message_backend_str[message_type], message_len, message_ptr + 5);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// 戻る
			return -1;
			break;
	}
	return api_result;
}

// --------------------------------
// PostgreSQL側メッセージ処理 ※この処理はアイドルイベント時にのみ、溜まっているメッセージ用キューのログへの出力として呼び出される。なので、PostgreSQLの状態は2より大きいはず。
// --------------------------------
int API_pgsql_server_message(struct EVS_ev_message_t *message_info)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

////    struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;

	char                            *message_ptr = message_info->message_ptr;
	unsigned int                    message_len = message_info->message_len;

	unsigned char                   *target_ptr;

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): START! message_len=%d, pgsql_status=%d\n", __func__, message_info->pgsql_socket_fd, message_info->message_len, message_info->pgsql_status);
	logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));

	// PostgreSQL用受信バッファが解析できる限り、ループ
	while (1)
	{
		// PostgreSQLの状態が、10:透過モードでないなら
		if (message_info->pgsql_status != 10)
		{
			// エラー
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal PostgreSQL Status(=%d)!?\n", __func__, message_info->pgsql_socket_fd, message_info->pgsql_status);
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// 戻る
			return -1;
		}

		// メッセージ長を取得(int32)
		target_ptr = (unsigned char *)&message_len;
		*target_ptr =  message_ptr[4];
		target_ptr ++;
		*target_ptr =  message_ptr[3];
		target_ptr ++;
		*target_ptr =  message_ptr[2];
		target_ptr ++;
		*target_ptr =  message_ptr[1];

		// PostgreSQL側各種クエリレスポンス解析処理
		api_result = API_pgsql_message_decodequeryresponse(message_info, message_ptr, message_len);
		// 正常終了でないなら
		if (api_result != 0)
		{
			// 戻る
			return api_result;
		}

		// メッセージの先頭ポインタを更新
		message_ptr += message_len + 1;
		// メッセージの先頭ポインタが、PostgreSQLからのメッセージ長を超えたら 
		if (message_ptr >= (char *)(message_info->message_ptr + message_info->message_len))
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Message END!\n", __func__, message_info->pgsql_socket_fd);
			logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));
			// while()を抜ける
			break;
		}
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): END!\n", __func__, message_info->pgsql_socket_fd);
	logging(LOG_DIRECT, LOGLEVEL_DEBUG, &(message_info->message_tv), NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return api_result;
}

// --------------------------------
// PostgreSQL側処理
// --------------------------------
int API_pgsql_server(struct EVS_ev_pgsql_t *this_pgsql)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;

	char                            *message_ptr = this_pgsql->recv_buf;
	unsigned int                    message_len = this_pgsql->recv_len;

	unsigned char                   *target_ptr;

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): START! recv_len=%d, pgsql_status=%d\n", __func__, this_pgsql->socket_fd, this_pgsql->recv_len, this_pgsql->pgsql_status);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// PostgreSQLの状態が、2:接続中より大きいなら
	if (this_pgsql->pgsql_status > 2)
	{
		// ------------------------------------
		// 透過モード処理　※メッセージをその都度解析していたら遅くなるので、いったん接続状態になったら、メッセージをキューに入れて後で解析する
		// ------------------------------------
		struct EVS_ev_message_t         *message_info;                      // メッセージ用構造体ポインタ

		// メッセージ用構造体ポインタのメモリ領域を確保
		message_info = (struct EVS_ev_message_t *)calloc(1, sizeof(struct EVS_ev_message_t));
		// メモリ領域が確保できなかったら
		if (message_info == NULL)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot calloc message_info's memory? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return -1;
		}

		// メッセージ情報にメッセージの各種情報をコピー
		message_info->from_to = 112;                                        // メッセージの方向
		message_info->client_socket_fd = this_client->socket_fd;            // 接続してきたクライアントのファイルディスクリプタ
		message_info->client_status = this_client->client_status;           // クライアント毎の状態
		message_info->client_ssl_status = this_client->ssl_status;          // クライアント毎のSSL接続状態
		strcpy(message_info->client_addr_str, this_client->addr_str);       // クライアントのアドレス文字列

		message_info->pgsql_socket_fd = this_pgsql->socket_fd;              // 接続してきたクライアントのファイルディスクリプタ
		message_info->pgsql_status = this_pgsql->pgsql_status;              // クライアント毎の状態
		message_info->pgsql_ssl_status = this_pgsql->ssl_status;            // クライアント毎のSSL接続状態
		strcpy(message_info->pgsql_addr_str, this_pgsql->addr_str);         // クライアントのアドレス文字列

		gettimeofday(&message_info->message_tv, NULL);                      // 現在時刻を取得してmessage_info->message_tvに格納

		// 受信したデータ分だけメモリ確保
		message_info->message_ptr = malloc(this_pgsql->recv_len);
		// メモリ領域が確保できなかったら
		if (message_info->message_ptr == NULL)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Cannot calloc message_info->message_ptr's memory? errno=%d (%s)\n", __func__, this_client->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return -1;
		}
		// 受信したデータをコピー
		memcpy(message_info->message_ptr, this_pgsql->recv_buf, this_pgsql->recv_len);
		message_info->message_len = this_pgsql->recv_len;

		// --------------------------------
		// テールキュー処理
		// --------------------------------
		// テールキューの最後にこの接続の情報を追加する
		TAILQ_INSERT_TAIL(&EVS_message_tailq, message_info, entries);

		snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(message): OK.\n", __func__);
		logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

		// PostgreSQLから送られてきたクエリメッセージを、クライアントに対して送信する(PostgreSQL→クライアントは、そのままでは送らない)
		api_result = API_pgsql_client_send(this_client, this_pgsql->recv_buf, this_pgsql->recv_len);

		// 戻る
		return api_result;
	}
	//// 透過モード、ここまで

	// PostgreSQL用受信バッファが解析できる限り、ループ
	while (1)
	{
		// PostgreSQLの状態が、0:未接続、もしくは1:接続開始や2:接続中以外なら
		if (this_pgsql->pgsql_status == 0 ||
			this_pgsql->pgsql_status > 2)
		{
			// エラー
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Illegal PostgreSQL Status(=%d)!?\n", __func__, this_pgsql->socket_fd, this_pgsql->pgsql_status);
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// 戻る
			return -1;
		}

		// メッセージ長を取得(int32)
		target_ptr = (unsigned char *)&message_len;
		*target_ptr =  message_ptr[4];
		target_ptr ++;
		*target_ptr =  message_ptr[3];
		target_ptr ++;
		*target_ptr =  message_ptr[2];
		target_ptr ++;
		*target_ptr =  message_ptr[1];

		// ------------------------------------
		// PostgreSQLからのメッセージ解析
		// ------------------------------------
		// PostgreSQLの状態が、1:接続開始なら
		if (this_pgsql->pgsql_status == 1)
		{
			// PostgreSQL側開始メッセージレスポンス解析処理
			api_result = API_pgsql_server_decodestartresponse(this_pgsql, message_ptr, message_len);
			// 正常終了でないなら
			if (api_result != 0)
			{
				// 戻る
				return api_result;
			}
		}

		// PostgreSQLの状態が、2:接続中なら
		if (this_pgsql->pgsql_status == 2)
		{
			// PostgreSQL側各種クエリレスポンス解析処理
			api_result = API_pgsql_server_decodequeryresponse(this_pgsql, message_ptr, message_len);
			// 正常終了でないなら
			if (api_result != 0)
			{
				// 戻る
				return api_result;
			}
		}

		// メッセージの先頭ポインタを更新
		message_ptr += message_len + 1;
		// メッセージの先頭ポインタが、PostgreSQLからのメッセージ長を超えたら 
		if (message_ptr >= this_pgsql->recv_buf + this_pgsql->recv_len)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Message END!\n", __func__, this_pgsql->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// while()を抜ける
			break;
		}
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): END!\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return api_result;
}

// --------------------------------------------------------------------------------------------------------------------------------
// ↑PostgreSQLからの受信関係
// --------------------------------------------------------------------------------------------------------------------------------
// ↓PostgreSQLからの受信時のコールバック関数
// --------------------------------------------------------------------------------------------------------------------------------
// --------------------------------
// PostgreSQL受信(recv : PostgreSQLからメッセージが送られてきたときに発生するイベント)のコールバック処理
// --------------------------------
static void CB_pgsqlrecv(struct ev_loop* loop, struct ev_io *watcher, int revents)
{
	int                             socket_result;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = (struct EVS_ev_pgsql_t *)watcher;         // libevから渡されたwatcherポインタを、本来の拡張構造体ポインタとして変換する

	char                            *msg_ptr = NULL;                    // 受信データ格納開始ポインタ
	ssize_t                         msg_limit = 0;                      // 受信可能データ長

	// イベントにエラーフラグが含まれていたら
	if (EV_ERROR & revents)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Invalid event!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		return;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): OK. ssl_status=%d\n", __func__, this_pgsql->socket_fd, this_pgsql->ssl_status);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

/*  // PostgreSQLについては無通信タイムアウトチェックをひとまず実装しないことにする
	// ----------------
	// 無通信タイムアウトチェックをする(=1:有効)なら
	// ----------------
	if (EVS_config.nocommunication_check == 1)
	{
		ev_now_update(loop);                                            // イベントループの日時を現在の日時に更新
		this_pgsql->last_activity = ev_now(loop);                       // 最終アクティブ日時(監視対象が最後にアクティブとなった日時)を設定する
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): last_activity=%.0f\n", __func__, this_pgsql->socket_fd, this_pgsql->last_activity);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
/* アイドルイベントはあくまでログメッセージ出力用なので、無通信タイムアウトチェックは、タイマーなどでしないといけない
		// ----------------
		// アイドルイベント開始処理                                                 ←PostgreSQLについてのタイムアウトを実装するなら、別イベントループを生成しないとダメだョ
		// ----------------
		// ev_idle_start()自体は、accept()とrecv()系イベントで呼び出す
		ev_idle_start(loop, &idle_pgsql_watcher);
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_idle_start(idle_pgsql_watcher): OK.\n", __func__);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}
*/
	// ----------------
	// 非SSL通信(=0)なら
	// ----------------
	if (this_pgsql->ssl_status == 0)
	{
		// ----------------
		// ソケット受信(recv : ソケットのファイルディスクリプタから、受信データ格納開始ポインタに受信可能データ長だけメッセージを受信する。(ノンブロッキングにするなら0ではなくてMSG_DONTWAIT)
		// ----------------
		socket_result = recv(this_pgsql->socket_fd, (void *)this_pgsql->recv_buf, MAX_RECV_BUF_LENGTH, 0);

		// 読み込めたメッセージ量が負(<0)だったら(エラーです)
		if (socket_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot recv message? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
			// ----------------
			CLOSE_pgsql(loop, (struct ev_io *)this_pgsql, revents);
			// アイドルイベント開始(メッセージ用キュー処理)
			ev_idle_start(loop, &idle_message_watcher);
			return;
		}
		// 読み込めたメッセージ量が0だったら(切断処理をする)
		else if (socket_result == 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): socket_result == 0.\n", __func__, this_pgsql->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
			// ----------------
			CLOSE_pgsql(loop, (struct ev_io *)this_pgsql, revents);
			// アイドルイベント開始(メッセージ用キュー処理)
			ev_idle_start(loop, &idle_message_watcher);
			return;
		}
		// PostgreSQLへの接続状態が、3:レスポンスデータ待ちでないなら
		if (this_pgsql->pgsql_status != 3)
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_pgsql->recv_len = socket_result;
			this_pgsql->recv_buf[this_pgsql->recv_len] = '\0';

			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Recieved %d bytes, recv_len=%d. A\n", __func__, this_pgsql->socket_fd, socket_result, this_pgsql->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
		// クライアント毎の状態が、3:レスポンスデータ待ちなら
		else
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_pgsql->recv_len += socket_result;
			this_pgsql->recv_buf[this_pgsql->recv_len] = '\0';

			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Recieved %d bytes, recv_len=%d. B\n", __func__, this_pgsql->socket_fd, socket_result, this_pgsql->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
	}
	// ----------------
	// SSLハンドシェイク中なら
	// ----------------
	else if (this_pgsql->ssl_status == 1)
	{
		// 対PostgreSQL(クライアントとして動作)の場合には、接続からハンドシェイクがうまくいったかどうかまで、API_pgsql_server_decodestartresponse()で処理しないといけない
		// が、PostgreSQLとのやり取りをするということは、CB_pgsqlrecv()が呼ばれるのでハンドシェイク中に呼ばれた場合にはスルーしないといけない
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Recieved msg_len=%d.\n", __func__, this_pgsql->socket_fd, this_pgsql->recv_len);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		return;
	}
	// ----------------
	// SSL接続中なら
	// ----------------
	else if (this_pgsql->ssl_status == 2)
	{
		// ----------------
		// OpenSSL(SSL_read : SSLデータ読み込み)
		// ----------------
		socket_result = SSL_read(this_pgsql->ssl, (void *)this_pgsql->recv_buf, MAX_RECV_BUF_LENGTH);

		// 読み込めたメッセージ量が負(<0)だったら(エラーです)
		if (socket_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_read(): Cannot read decrypted message!?\n", __func__, this_pgsql->socket_fd, ERR_reason_error_string(ERR_get_error()));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
			// ----------------
			CLOSE_pgsql(loop, (struct ev_io *)this_pgsql, revents);
			// アイドルイベント開始(メッセージ用キュー処理)
			ev_idle_start(loop, &idle_message_watcher);
			return;
		}
		// 読み込めたメッセージ量が0だったら(切断処理をする)
		if (socket_result == 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): socket_result == 0.\n", __func__, this_pgsql->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
			// ----------------
			CLOSE_pgsql(loop, (struct ev_io *)this_pgsql, revents);
			// アイドルイベント開始(メッセージ用キュー処理)
			ev_idle_start(loop, &idle_message_watcher);
			return;
		}

		// PostgreSQLへの接続状態が、3:レスポンスデータ待ちでないなら
		if (this_pgsql->pgsql_status != 3)
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_pgsql->recv_len = socket_result;
			this_pgsql->recv_buf[this_pgsql->recv_len] = '\0';

			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Recieved %d bytes, recv_len=%d. C\n", __func__, this_pgsql->socket_fd, socket_result, this_pgsql->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
		// クライアント毎の状態が、3:レスポンスデータ待ちなら
		else
		{
			// メッセージ長を設定する(メッセージの終端に'\0'(!=NULL)を設定してはっきりとさせておく)
			this_pgsql->recv_len += socket_result;
			this_pgsql->recv_buf[this_pgsql->recv_len] = '\0';

			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Recieved %d bytes, recv_len=%d. D\n", __func__, this_pgsql->socket_fd, socket_result, this_pgsql->recv_len);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
		}
	}

	// --------------------------------
	// API関連
	// --------------------------------
	// API開始処理(PostgreSQL処理分岐)
	socket_result = API_pgsql_server(this_pgsql);           // この関数はPostgreSQL用なので、api_start()を経由せず、直接API_pgsql()を呼んでる

	// APIの処理結果がエラー(=-1)だったら(切断処理をする)
	if (socket_result != 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): API ERROR!? socket_result=%d\n", __func__, this_pgsql->socket_fd, socket_result);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		// ----------------
		// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
		// ----------------
		CLOSE_pgsql(loop, (struct ev_io *)this_pgsql, revents);
		// アイドルイベント開始(メッセージ用キュー処理)
		ev_idle_start(loop, &idle_message_watcher);
		return;
	}

	// アイドルイベント開始(メッセージ用キュー処理)
	ev_idle_start(loop, &idle_message_watcher);
	return;
}

// --------------------------------------------------------------------------------------------------------------------------------
// ↑PostgreSQLからの受信時のコールバック関数
// --------------------------------------------------------------------------------------------------------------------------------
// ↓PostgreSQLへの送信関係
// --------------------------------------------------------------------------------------------------------------------------------
// --------------------------------
// PostgreSQL送信処理
// --------------------------------
int API_pgsql_server_send(struct EVS_ev_pgsql_t *this_pgsql, unsigned char *message_ptr, int message_len)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;

	// ----------------
	// 非SSL通信(=0)なら
	// ----------------
	if (this_pgsql->ssl_status == 0)
	{
		// ----------------
		// ソケット送信(send : ソケットのファイルディスクリプタに対して、msg_bufからmsg_lenのメッセージを送信する。(ノンブロッキングにするなら0ではなくてMSG_DONTWAIT)
		// ----------------
		api_result = send(this_pgsql->socket_fd, (void*)message_ptr, message_len, 0);
		// 送信したバイト数が負(<0)だったら(エラーです)
		if (api_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): send(): Cannot send message? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return api_result;
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): send(): OK. length=%d\n", __func__, this_pgsql->socket_fd, message_len);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}
	// ----------------
	// SSLハンドシェイク中なら
	// ----------------
	else if (this_pgsql->ssl_status == 1)
	{
		// ERROR!?!? (TBD)
	}
	// ----------------
	// SSL接続中なら
	// ----------------
	else if (this_pgsql->ssl_status == 2)
	{
		// ----------------
		// OpenSSL(SSL_write : SSLデータ書き込み)
		// ----------------
		api_result = SSL_write(this_pgsql->ssl, (void*)message_ptr, message_len);
		// 送信したバイト数が負(<0)だったら(エラーです)
		if (api_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_write(): Cannot write encrypted message!?\n", __func__, this_pgsql->socket_fd, ERR_reason_error_string(ERR_get_error()));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return api_result;
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_write(): OK. length=%d\n", __func__, this_pgsql->socket_fd, message_len);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	}
	// 戻る
	return 0;
}

// --------------------------------
// PostgreSQL PasswordMessage(MD5)処理 (※ソルトキーはthis_pgsql->recv_buf + 9から4バイトで入っている)
// --------------------------------
int API_pgsql_send_PasswordMessageMD5(struct EVS_ev_pgsql_t *this_pgsql)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;
	struct EVS_db_t                 *db_info = (struct EVS_db_t *)this_pgsql->db_info;

	char                            *hash_type = {"md5"};               // ハッシュ化タイプ("md5", "sha256"など)

	char                            *hash_passwordusername;             // gethashdata(password+username)のハッシュ化データ格納ポインタ
	char                            *hash_data;                         // gethashdata("md5" + gethashdata(password+username) + salt_key)のハッシュ化データ格納ポインタ
	int                             hash_len;

	char                            *message_ptr = this_pgsql->recv_buf;
	unsigned int                    message_len;

	// ----------------
	// gethashdata(password+username)のハッシュ化データ格納ポインタのメモリ領域を確保(EVP_MAX_MD_SIZE*2 + \0分でいいんだけど、面倒なのでMAX_SIZE_1K)
	// ----------------
	hash_passwordusername = (char *)calloc(1, MAX_SIZE_1K);
	// メモリ領域が確保できなかったら
	if (hash_passwordusername == NULL)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot calloc hash_passwordusername's memory? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}
	// ----------------
	// 暗号化データ生成(暗号化方式(文字列で"md5", "sha256"など)、暗号対象データ、暗号対象データ長、ソルトデータ、ソルトデータ長、ハッシュ化データ格納ポインタ)
	// ----------------
	hash_len = gethashdata(hash_type, db_info->password, strlen(db_info->password), db_info->username, strlen(db_info->username), hash_passwordusername);
	if (hash_len == -1)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): gethashdata() error!?\n", __func__, this_pgsql->socket_fd);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(hash_passwordusername);
		return -1;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): hash_passwordusername's hash_len=%d\n", __func__, this_pgsql->socket_fd, hash_len);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// gethashdata("md5" + gethashdata(password+username) + salt_key)のハッシュ化データ格納ポインタのメモリ領域を確保 (PasswordMessage:5 + strlen(hash_type) + EVP_MAX_MD_SIZE*2 + \0分)
	// ----------------
	hash_data = (char *)calloc(1, 5 + strlen(hash_type) + (EVP_MAX_MD_SIZE * 2) + 1);
	// メモリ領域が確保できなかったら
	if (hash_data == NULL)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot calloc hash data's memory? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(hash_passwordusername);
		return -1;
	}
	// PasswordMessageのメッセージタイプをハッシュ化データ格納ポインタの先頭にコピー
	hash_data[0] = 'p';
	// ※PasswordMessageのメッセージ長は後で設定
	// ハッシュ化タイプ文字列をハッシュ化データ格納ポインタにコピー
	snprintf(hash_data + 5, strlen(hash_type) + 1, "%s", hash_type);
	// ----------------
	// 暗号化データ生成(暗号化方式(文字列で"md5", "sha256"など)、暗号対象データ、暗号対象データ長、ソルトデータ、ソルトデータ長、ハッシュ化データ格納ポインタ)
	// ----------------
	hash_len = gethashdata(hash_type, hash_passwordusername, hash_len, message_ptr + 9, 4, hash_data + 5 + strlen(hash_type));
	if (hash_len == -1)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): gethashdata() error!?\n", __func__, this_pgsql->socket_fd);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(hash_data);
		free(hash_passwordusername);
		return -1;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): hash_data's hash_len=%d\n", __func__, this_pgsql->socket_fd, hash_len);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// PasswordMessageのメッセージ長を設定(最初の'p'の分は除く)
	message_len = 4 + strlen(hash_type) + hash_len + 1;
	hash_data[4] = *(char *)&message_len;
	hash_data[3] = *((char *)&message_len + 1);
	hash_data[2] = *((char *)&message_len + 2);
	hash_data[1] = *((char *)&message_len + 3);

	// PostgreSQL送信処理(メッセージタイプの1+を忘れずに)
	api_result = API_pgsql_server_send(this_pgsql, hash_data, 1 + message_len);
	// 正常終了でないなら
	if (api_result != 0)
	{
		free(hash_data);
		free(hash_passwordusername);
		// 戻る
		return api_result;
	}

	// ダンプ出力(メッセージタイプの1+を忘れずに)
	dump2log(LOG_QUEUEING, LOGLEVEL_DUMP, NULL, (void *)hash_data, (1 + message_len) & 0x3FF);

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> PostgreSQL(%s) PasswordMessage(MD5). (message size=%d, len=0x%02x)\n", db_info->hostname, 1 + message_len, message_len);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	free(hash_data);
	free(hash_passwordusername);

	// 戻る
	return api_result;
}

// --------------------------------
// PostgreSQL StartupMessage送信処理 (※この関数を呼ぶ時には、this_client->param_infoに完璧なデータが入っている前提)
// --------------------------------
int API_pgsql_send_StartupMessage(struct EVS_ev_pgsql_t *this_pgsql)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_client_t          *this_client = (struct EVS_ev_client_t *)this_pgsql->client_info;
	struct EVS_db_t                 *db_info = (struct EVS_db_t *)this_pgsql->db_info;

	char                            pgsql_message[MAX_SIZE_1K] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, };
	unsigned int                    message_len = 0;

	char                            *target_ptr;

	// コピー先ポインタを設定
	target_ptr = pgsql_message + 8;

	// メッセージバッファにデータベース名をコピー
	strcpy(target_ptr, "database");
	// コピー先ポインタを移動(\0分を忘れずに)
	target_ptr += strlen(target_ptr) + 1;
	strcpy(target_ptr, db_info->database);
	// コピー先ポインタを移動(\0分を忘れずに)
	target_ptr += strlen(target_ptr) + 1;

	// メッセージバッファにユーザー名をコピー
	strcpy(target_ptr, "user");
	// コピー先ポインタを移動(\0分を忘れずに)
	target_ptr += strlen(target_ptr) + 1;
	strcpy(target_ptr, db_info->username);
	// コピー先ポインタを移動(\0分を忘れずに)
	target_ptr += strlen(target_ptr) + 1;

	// メッセージバッファにアプリケーション名をコピー(必要なのかな!?)
	strcpy(target_ptr, "application_name");
	// コピー先ポインタを移動(\0分を忘れずに)
	target_ptr += strlen(target_ptr) + 1;
	strncpy(target_ptr, EVS_NAME, strlen(EVS_NAME));
	// コピー先ポインタを移動(\0分を忘れずに)
	target_ptr += strlen(target_ptr) + 1;

	// メッセージ長を設定(StartupMessageは0x00,0x00で終わる事!!)
	message_len = target_ptr - pgsql_message + 1;
	pgsql_message[3] = *(char *)&message_len;
	pgsql_message[2] = *((char *)&message_len + 1);
	pgsql_message[1] = *((char *)&message_len + 2);
	pgsql_message[0] = *((char *)&message_len + 3);

	// PostgreSQL送信処理(これはStartupMessageなのでメッセージタイプはないから1+しない)
	api_result = API_pgsql_server_send(this_pgsql, pgsql_message, message_len);
	// 正常終了でないなら
	if (api_result != 0)
	{
		// 戻る
		return api_result;
	}

	// ダンプ出力(これはStartupMessageなのでメッセージタイプはないから1+しない)
	dump2log(LOG_QUEUEING, LOGLEVEL_DUMP, NULL, (void *)pgsql_message, message_len & 0x3FF);

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> PostgreSQL(%s) StartupMessage. (message size=%d, len=0x%02x)\n", db_info->hostname, message_len, message_len);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return api_result;
}

// --------------------------------
// PostgreSQL SSLRequest送信処理
// --------------------------------
int API_pgsql_send_SSLRequest(struct EVS_ev_pgsql_t *this_pgsql)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_db_t                 *db_info = (struct EVS_db_t *)this_pgsql->db_info;

	const char                      pgsql_message[] = {0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f};

	// ----------------
	// ソケット送信(send : PostgreSQLに対して、SSLRequestを送信する ※この時点ではまだSSL接続はしていないので、わざわざAPI_pgsql_server_send()はつかわない)
	// ----------------
	api_result = send(this_pgsql->socket_fd, (void *)pgsql_message, 8, 0);
	// 送信したバイト数が負(<0)だったら(エラーです)
	if (api_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): send(): Cannot send message? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// ダンプ出力
	dump2log(LOG_QUEUEING, LOGLEVEL_DUMP, NULL, (void *)pgsql_message, 8);

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "PgAnalyzer -> PostgreSQL(%s) SSLRequest. (message size=%d, len=0x%02x)\n", db_info->hostname, 8, 8);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	return 0;
}

// --------------------------------
// PostgreSQL SSLハンドシェイク処理
// --------------------------------
int API_pgsql_SSLHandshake(struct EVS_ev_pgsql_t *this_pgsql)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	// SSLハンドシェイクを開始
	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL/TLS handshake START!\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// SSL設定情報を作成
	//     OpenSSL 1.1.0以降は初期化関数、OPENSSL_init_ssl()およびOPENSSL_init_crypto()を呼ぶ必要すらなくなったが、証明書ファイルの指定や、細かい制限をSSL_CTX_set_options()等でする必要はある
	//     サーバー用のTLSメソッドを指定、1.1.0以降はTLS_server_method()を指定すること。SSL_CTX_set_options()でいずれにしても許可するプロトコルバージョンを指定すること
	// ----------------
	this_pgsql->ctx = SSL_CTX_new(TLS_client_method());
	if (this_pgsql->ctx == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_CTX_new(): Cannot initialize SSL_CTX!? %s\n", __func__, this_pgsql->socket_fd, ERR_reason_error_string(ERR_get_error()));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}
	// SSL設定でTLSv1.2以上しか許可しない(1.1.0以降はSSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)、でいい)
////    SSL_CTX_set_options(EVS_ctx, (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1));
	SSL_CTX_set_min_proto_version(this_pgsql->ctx, TLS1_2_VERSION);

	// ----------------
	// OpenSSL(SSL_new : SSL設定情報を参照して、SSL接続情報を新規に取得)
	// ----------------
	this_pgsql->ssl = SSL_new(this_pgsql->ctx);
	if (this_pgsql->ssl == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_new(): Cannot get SSL!? %s\n", __func__, this_pgsql->socket_fd,ERR_reason_error_string(ERR_get_error()));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// ----------------
	// OpenSSL(SSL_set_fd : SSL設定情報とPosgtreSQLと接続しているファイルディスクリプタを紐づけ)
	// ----------------
	api_result = SSL_set_fd(this_pgsql->ssl, this_pgsql->socket_fd);
	if (api_result == 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_CTX_new(): Cannot set SSL_set_fd!? %s\n", __func__, this_pgsql->socket_fd, ERR_reason_error_string(ERR_get_error()));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return  -1;
	}

	// 対PostgreSQL(クライアントとして動作)の場合には、接続からハンドシェイクがうまくいったかどうかまで、API_pgsql_server_decodestartresponse()で処理しないといけない
	// が、PostgreSQLとのやり取りをするということは、CB_pgsqlrecv()が呼ばれるのでハンドシェイク中に呼ばれた場合にはスルーしないといけない

	// ----------------
	// OpenSSL(SSL_connect : PosgtreSQLに対してSSL接続開始)
	// ----------------
	api_result = SSL_connect(this_pgsql->ssl);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_connect(): api_result=%d.\n", __func__, this_pgsql->socket_fd, api_result);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// SSL/TLSハンドシェイクの結果コードを取得
	api_result = SSL_get_error(this_pgsql->ssl, api_result);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL_get_error(): api_result=%d.\n", __func__, this_pgsql->socket_fd, api_result);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// SSL/TLSハンドシェイクの結果コード別処理分岐
	switch (api_result)
	{
		case SSL_ERROR_NONE : 
			// エラーなし(ハンドシェイク成功)
			// SSL接続中に設定
			this_pgsql->ssl_status = 2;
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): SSL/TLS handshake OK.\n", __func__, this_pgsql->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
			// PostgreSQL StartupMessage送信処理 (※この関数を呼ぶ時には、this_client->param_infoに完璧なデータが入っている前提)
			api_result = API_pgsql_send_StartupMessage(this_pgsql);
			// 戻る
			return api_result;
			break;
		case SSL_ERROR_SSL :
		case SSL_ERROR_SYSCALL :
			// SSL/TLSハンドシェイクがエラー
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot SSL/TLS handshake!? %s\n", __func__, this_pgsql->socket_fd, ERR_reason_error_string(ERR_get_error()));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			// ----------------
			// PostgreSQL接続終了処理(バッファ開放、ソケットクローズ、PostgreSQL用キューからの削除、イベントの停止)
			// ----------------
			CLOSE_pgsql(EVS_loop, (struct ev_io *)this_pgsql, api_result);                     // ここではEVS_loopを直接指定
			// 戻る
			return -1;
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
	return 0;
}

// --------------------------------
// サーバー接続開始処理(IPv4/IPv6接続)
// --------------------------------
int API_pgsql_server_start_inet(struct EVS_ev_client_t *this_client)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = this_client->pgsql_info;
	char                            **db_param = this_client->param_info;

	struct addrinfo                 target_hints;                       // 接続先のアドレス構造体を取得するための条件
	struct addrinfo                 *target_addrinfo, *addrinfo_ptr;    // 接続先のアドレス構造体ポインタ

	struct EVS_db_t                 *db_info;                           // データベース別設定用構造体ポインタ

	db_info = this_pgsql->db_info;

	// ----------------
	// 接続先のアドレス構造体取得
	// ----------------
	// https://linuxjm.osdn.jp/html/LDP_man-pages/man3/getaddrinfo.3.html
	// 接続先のアドレス構造体を初期化
	memset(&target_hints, 0, sizeof(struct addrinfo));
	// 接続先のアドレス構造体を取得するための条件を設定
	target_hints.ai_family = AF_UNSPEC;                                 // IPv4でもIPv6でもどちらが返って来てもよい
	target_hints.ai_socktype = SOCK_STREAM;                             // ストリームソケット
	target_hints.ai_protocol = 0;                                       // どんなプロトコルでもOK
	target_hints.ai_flags = 0;                                          // 追加オプション無し

	// 接続先のアドレス構造体取得
	api_result = getaddrinfo(db_info->hostname, db_info->servicename, &target_hints, &target_addrinfo);
	// 接続先のアドレス構造体が得られないなら
	if (api_result != 0)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot get PostgreSQL's address info!? errno=%d (%s)\n", __func__, api_result, gai_strerror(api_result));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// 得られた接続先に対して順番に接続を試してみる
	for (addrinfo_ptr = target_addrinfo; addrinfo_ptr != NULL; addrinfo_ptr = addrinfo_ptr->ai_next)
	{
		// ----------------
		// ソケット生成(socket : UNIXドメインソケットでかつストリームで)
		// ----------------
		api_result = socket(addrinfo_ptr->ai_family, addrinfo_ptr->ai_socktype, addrinfo_ptr->ai_protocol);
		// ソケット生成が出来なかったら
		if (api_result == -1)
		{
			// エラー…ではなくて、次のアドレス構造体に対してソケット生成を試す
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): socket(%s, SOCK_STREAM, 0): Cannot create new socket? errno=%d (%s)\n", __func__, pf_name_list[addrinfo_ptr->ai_family], errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			continue;
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): socket(%s, SOCK_STREAM, 0): Create new socket. fd=%d\n", __func__, pf_name_list[addrinfo_ptr->ai_family], api_result);
		logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
		// ソケットディスクリプタを設定
		this_pgsql->socket_fd = api_result;
		
		// ----------------
		// ソケット接続(connect : ソケットのファイルディスクリプタと、ソケットアドレスを紐づけ)
		// ----------------
		if (connect(this_pgsql->socket_fd, addrinfo_ptr->ai_addr, addrinfo_ptr->ai_addrlen) != -1)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot connect PostgreSQL!? try to next address info\n", __func__, this_pgsql->socket_fd);
			logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
			// 接続できたのでfor文を抜ける
			break;
		}

		// ここに来た、ということはソケットは生成できたけど接続までは行かなかったので…
		// ソケットを閉じる
		api_result = close(this_pgsql->socket_fd);
		// ソケットのクローズ結果がエラーだったら
		if (api_result < 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): close(): Cannot socket close? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
			logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
			return -1;
		}
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): Cannot connect PostgreSQL!? try to next address info\n", __func__, this_pgsql->socket_fd);
		logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
	}
	// 全てのアドレス構造体に対して接続を試したが接続ができなかったら
	if (addrinfo_ptr == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): close(): Cannot socket close? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): connect(%s:%s): OK!\n", __func__, this_pgsql->socket_fd, db_info->hostname, db_info->servicename);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 接続先のアドレス構造体を解放
	freeaddrinfo(target_addrinfo);

	// PostgreSQL処理への接続情報構造体のその他の値を設定する
	ev_now_update(EVS_loop);                                            // イベントループの日時を現在の日時に更新
	this_pgsql->last_activity = ev_now(EVS_loop);                       // 最終アクティブ日時(PostgreSQLとのやり取りが最後にアクティブとなった日時)を設定する(※loopがないのでグローバル変数で)
	this_pgsql->client_info = (void *)this_client;                      // クライアント毎の付帯情報(HTTPのリクエストヘッダ情報とか)へのポインタを設定する

	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_pgsql_tailq, this_pgsql, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(pgsql=%d): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// libev 処理
	// --------------------------------
	// クライアント別設定用構造体ポインタのI/O監視オブジェクトに対して、コールバック処理とソケットファイルディスクリプタ、そしてイベントのタイプを設定する
	ev_io_init(&this_pgsql->io_watcher, CB_pgsqlrecv, this_pgsql->socket_fd, EV_READ);
	ev_io_start(EVS_loop, &this_pgsql->io_watcher);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_init(CB_pgsqlrecv, pgsql=%d, EV_READ): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_start(): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->pgsql_status %d -> 1!!\n", __func__, this_pgsql->socket_fd, this_pgsql->pgsql_status);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	// PostgreSQLへの接続状態を、1:接続開始に設定
	this_pgsql->pgsql_status = 1;

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Postgresql Connected.(%s, %s)\n", db_info->hostname, db_info->servicename);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// PostgreSQL SSLRequest送信処理
	api_result =  API_pgsql_send_SSLRequest(this_pgsql);

	return api_result;
}

// --------------------------------
// サーバー接続開始処理(UNIXドメインソケット)
// --------------------------------
int API_pgsql_server_start_unix(struct EVS_ev_client_t *this_client)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = this_client->pgsql_info;
	char                            **db_param = this_client->param_info;

	// ----------------
	// ソケット生成(socket : UNIXドメインソケットでかつストリームで)
	// ----------------
	this_pgsql->socket_address.sa_un.sun_family = PF_UNIX;    // プロトコルファミリーを設定
	api_result = socket(this_pgsql->socket_address.sa_un.sun_family, SOCK_STREAM, 0);
	// ソケット生成が出来なかったら
	if (api_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): socket(%s, SOCK_STREAM): Cannot create new socket? errno=%d (%s)\n", __func__, pf_name_list[this_pgsql->socket_address.sa_un.sun_family], errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(this_pgsql);
		this_pgsql = NULL;
		return -1;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): socket(%s, SOCK_STREAM): Create new socket. pgsql=%d\n", __func__, pf_name_list[this_pgsql->socket_address.sa_un.sun_family], api_result);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ソケットディスクリプタを設定
	this_pgsql->socket_fd = api_result;
	// ソケットアドレス構造体に接続先(サーバー)を設定 (★とりあえずUNIXドメインソケットのみ対応)
	snprintf(this_pgsql->socket_address.sa_un.sun_path, MAX_STRING_LENGTH, "%s", "/tmp/.s.PGSQL.5432");

	// ----------------
	// 接続(connect : ソケットのファイルディスクリプタとUNIXドメインソケットアドレスを紐づけ)
	// ----------------
	api_result = connect(this_pgsql->socket_fd, (struct sockaddr *)&this_pgsql->socket_address.sa_un, sizeof(this_pgsql->socket_address.sa_un));
	// ソケットアドレスの紐づけが出来なかったら
	if (api_result < 0)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): connect(pgsql=%d, %s): Cannot socket binding? errno=%d (%s)\n", __func__, this_pgsql->socket_fd, this_pgsql->socket_address.sa_un.sun_path, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		free(this_pgsql);
		this_pgsql = NULL;
		return -1;
	}
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): connect(pgsql=%d, %s): OK!\n", __func__, this_pgsql->socket_fd, this_pgsql->socket_address.sa_un.sun_path);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// PostgreSQL処理への接続情報構造体のその他の値を設定する
	ev_now_update(EVS_loop);                                            // イベントループの日時を現在の日時に更新
	this_pgsql->last_activity = ev_now(EVS_loop);                       // 最終アクティブ日時(PostgreSQLとのやり取りが最後にアクティブとなった日時)を設定する(※loopがないのでグローバル変数で)
	this_pgsql->client_info = (void *)this_client;                      // クライアント毎の付帯情報(HTTPのリクエストヘッダ情報とか)へのポインタを設定する

	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_pgsql_tailq, this_pgsql, entries);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): TAILQ_INSERT_TAIL(pgsql=%d): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// libev 処理
	// --------------------------------
	// クライアント別設定用構造体ポインタのI/O監視オブジェクトに対して、コールバック処理とソケットファイルディスクリプタ、そしてイベントのタイプを設定する
	ev_io_init(&this_pgsql->io_watcher, CB_pgsqlrecv, this_pgsql->socket_fd, EV_READ);
	ev_io_start(EVS_loop, &this_pgsql->io_watcher);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_init(CB_pgsqlrecv, pgsql=%d, EV_READ): OK.\n", __func__, this_pgsql->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_io_start(): OK.\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	snprintf(log_str, MAX_LOG_LENGTH, "%s(pgsql=%d): this_pgsql->pgsql_status %d -> 1!!\n", __func__, this_pgsql->socket_fd, this_pgsql->pgsql_status);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));
	// PostgreSQLへの接続状態を、1:接続開始に設定
	this_pgsql->pgsql_status = 1;

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Postgresql Connected. (%s)\n", this_pgsql->socket_address.sa_un.sun_path);
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// PostgreSQL StartupMessage送信処理 (※この関数を呼ぶ時には、this_client->param_infoに完璧なデータが入っている前提)
	api_result = API_pgsql_send_StartupMessage(this_pgsql);

	return api_result;
}

// --------------------------------
// サーバー接続開始処理
// --------------------------------
int API_pgsql_server_start(struct EVS_ev_client_t *this_client)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = NULL;                 // この関数でpgsql_infoの領域を確保するので、初期化ではNULLにしておく
	char                            **param_info = this_client->param_info;

	struct EVS_db_t                 *db_list;                           // データベース別設定用構造体ポインタ

	// とりあえず表示する
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): START! (database=%s, username=%s)\n", __func__, this_client->socket_fd, param_info[CLIENT_DATABASE], param_info[CLIENT_USERNAME]);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// --------------------------------
	// データベース別処理(設定に、クライアントから指定されたユーザー名とデータベースに基づいたPostgreSQLの指定があるか探す)
	// --------------------------------
	// データベース用テールキューからポート情報を取得して全て処理
	TAILQ_FOREACH (db_list, &EVS_db_tailq, entries)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): db_list MATCH? database=%s, username=%s\n", __func__, db_list->database, db_list->username);
		logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

		// データベース名とユーザー名が合致していれば
		if (strcmp(param_info[CLIENT_DATABASE], db_list->database) == 0 && strcmp(param_info[CLIENT_USERNAME], db_list->username) == 0)
		{
			snprintf(log_str, MAX_LOG_LENGTH, "%s(): db_list MATCH! database=%s, username=%s\n", __func__, db_list->database, db_list->username);
			logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));
			api_result = 1;
			break;
		}
	}
	// 設定に、クライアントから指定されたユーザー名とデータベースに基づいたPostgreSQLの指定がないなら
	if (api_result != 1)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot find PostgreSQL setting!?\n", __func__);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// ----------------
	// PostgreSQL用構造体ポインタのメモリ領域を確保
	// ----------------
	this_client->pgsql_info = (struct EVS_ev_pgsql_t *)calloc(1, sizeof(struct EVS_ev_pgsql_t));
	// メモリ領域が確保できなかったら
	if (this_client->pgsql_info == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot calloc memory? errno=%d (%s)\n", __func__, errno, strerror(errno));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// 確保したPostgreSQL用構造体のPosgreSQLデータベース情報ポインタを設定
	this_pgsql = this_client->pgsql_info;
	this_pgsql->db_info = db_list;

	// --------------------------------
	// 指定されたPostgreSQLに対して接続
	// --------------------------------
	// 設定で指定されたPostgreSQLへの接続がUNIXドメインソケットなら
	if (strcmp(db_list->hostname, "UNIXSOCKET") == 0)
	{
		// サーバー接続開始処理(UNIXドメインソケット)
		api_result = API_pgsql_server_start_unix(this_client);
	}
	// それ以外は
	else
	{
		// サーバー接続開始処理(IPv4/IPv6接続)
		api_result = API_pgsql_server_start_inet(this_client);
	}
	return api_result;
}
