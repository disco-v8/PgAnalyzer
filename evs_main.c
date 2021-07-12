// ----------------------------------------------------------------------
// Protocol Analyzer for PostgreSQL -
// Purpose:
//     Base process of Server and Client.
//
// Version:
//     0.0.16 Published on GitHUB.
//     0.0.17 Fix Timeout.
//     0.0.18 Fix Idle Events.
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
static const char _base64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char b64lookup[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
};

// ----------------------------------------------------------------------
// コード部分
// ----------------------------------------------------------------------
// --------------------------------
// ダンプ文字列生成処理(dump_strに対して、targetdataからtagetlenバイトのダンプ文字列を設定して返す)
// --------------------------------
char *getdumpstr(void *targetdata, int targetlen)
{
	char                        *dump_str = NULL;                       // ダンプ結果文字列ポインタ
	char                        *dump_hex_pos;                          // ダンプ結果HEX文字位置
	char                        *dump_char_pos;                         // ダンプ結果CHAR文字位置

	unsigned char               *target_ptr;                            // 対象データポインタ
	int                         target_column;                          // 対象表示文字位置

	// ダンプ結果文字列は最低でも16バイト分の文字列＝70文字(\n\0含む)になる
	dump_str = (char *)calloc(1, ((targetlen + 16 - 1) / 16) * 70);
	if (dump_str == NULL)
	{
		return dump_str;
	}
	
	// ダンプ結果HEX文字位置を設定
	dump_hex_pos = dump_str;
	// ダンプ結果CHAR文字位置を設定
	dump_char_pos = dump_hex_pos + 52;

	// 対象データポインタに、対象データの最初のバイトポインタを設定して、長さ分だけループ
	for (target_ptr = (unsigned char *)targetdata; target_ptr < (unsigned char *)targetdata + targetlen; )
	{
		// 8バイト分ループ
		for (target_column = 0; target_column < 8; target_column++)
		{
			// まずは上位4ビットを一文字分設定
			*dump_hex_pos = *target_ptr;    // 0xb6
			*dump_hex_pos >>= 4;            // 0x0b
			*dump_hex_pos &= 0x0F;          // 0x0b
			if (*dump_hex_pos >= 0x00 && *dump_hex_pos <= 0x09)
			{
				*dump_hex_pos += 0x30;      // 0x30..0x39
			}
			else
			{
				*dump_hex_pos += 0x57;      // 0x61..0x66
			}
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;

			// 次に下位4ビットを一文字分設定
			*dump_hex_pos = *target_ptr;    // 0x4a
			*dump_hex_pos &= 0x0F;          // 0x0a
			if (*dump_hex_pos >= 0x00 && *dump_hex_pos <= 0x09)
			{
				*dump_hex_pos += 0x30;      // 0x30..0x39
			}
			else
			{
				*dump_hex_pos += 0x57;      // 0x61..0x66
			}
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;

			// スペース一つあけて
			*dump_hex_pos = ' ';
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;

			if (*target_ptr >= 0x20 && *target_ptr <= 0x7e)
			{
				*dump_char_pos = *target_ptr;
			}
			else
			{
				*dump_char_pos = '.';
			}
			// ダンプ結果CHAR文字位置を+1進める
			dump_char_pos += 1;
			// 対象データポインタを+1進める
			target_ptr++;
		}

		// スペース一つあける
		*dump_hex_pos = ' ';
		*dump_char_pos = ' ';
		// ダンプ結果HEX文字位置を+1進める
		dump_hex_pos += 1;
		// ダンプ結果CHAR文字位置を+1進める
		dump_char_pos += 1;

		// 8バイト分ループ
		for (target_column = 0; target_column < 8; target_column++)
		{
			// まずは上位4ビットを一文字分設定
			*dump_hex_pos = *target_ptr;    // 0x30
			*dump_hex_pos >>= 4;            // 0x03
			*dump_hex_pos &= 0x0F;          // 0x03
			if (*dump_hex_pos >= 0x00 && *dump_hex_pos <= 0x09)
			{
				*dump_hex_pos += 0x30;      // 0x30..0x39
			}
			else
			{
				*dump_hex_pos += 0x57;      // 0x61..0x66
			}
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;

			// 次に下位4ビットを一文字分設定
			*dump_hex_pos = *target_ptr;    // 0x30
			*dump_hex_pos &= 0x0F;          // 0x00
			if (*dump_hex_pos >= 0x00 && *dump_hex_pos <= 0x09)
			{
				*dump_hex_pos += 0x30;      // 0x30..0x39
			}
			else
			{
				*dump_hex_pos += 0x57;      // 0x61..0x66
			}
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;

			// スペース一つあけて
			*dump_hex_pos = ' ';
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;

			if (*target_ptr >= 0x20 && *target_ptr <= 0x7e)
			{
				*dump_char_pos = *target_ptr;
			}
			else
			{
				*dump_char_pos = '.';
			}
			// ダンプ結果CHAR文字位置を+1進める
			dump_char_pos += 1;
			// 対象データポインタを+1進める
			target_ptr++;
		}

		// 3バイト分ループ
		for (target_column = 0; target_column < 3; target_column++)
		{
			// スペース一つあけて
			*dump_hex_pos = ' ';
			// ダンプ結果HEX文字位置を+1進める
			dump_hex_pos += 1;
		}

		// まだデータがあるなら
		if (target_ptr < (unsigned char *)targetdata + targetlen)
		{
			// 改行(=0x0a)をつける
			*dump_char_pos = 0x0A;
		}
		// そうではないなら
		else
		{
			// 文字列の終わり(=0x00)を設定する
			*dump_char_pos = 0x00;            
		}
		// ダンプ結果HEX文字位置を改行の次(+1)に進める
		dump_hex_pos = dump_char_pos + 1;
		// ダンプ結果CHAR文字位置を+52進める
		dump_char_pos = dump_hex_pos + 52;
	}
	return dump_str;
}

// --------------------------------
// ダンプ出力
// --------------------------------
void dump2log(int log_type, int log_level, struct timeval *log_tv, void *target_data, int taget_len)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	char                            *dump_str;
	char                            *null_str = {"Cannot DUMP!?\n"};

	// ログレベル(log_level)が設定値未満なら
	if (log_level < EVS_config.log_level)
	{
		// ログ出力しない
		return;
	}

	// 指定されたデータをダンプした文字列を取得
	dump_str = getdumpstr(target_data, taget_len);
	// ダンプデータが取得できなかったら
	if (dump_str == NULL)
	{
		// ダンプ出来なかった旨の文字列をダンプ文字列として設定
		dump_str = null_str;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "--------------------------------\n");
	logging(log_type, log_level, log_tv, NULL, NULL, log_str, strlen(log_str));

	// ダンプした文字列がMAX_LOG_LENGTH以上なら
	if (strlen(dump_str) >= MAX_LOG_LENGTH)
	{
		snprintf(log_str, MAX_LOG_LENGTH - 5, "%s", dump_str);
		sprintf(log_str + strlen(log_str), "...\n");
	}
	else
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s\n", dump_str);    // MAX_LOG_LENGTHを変えるな!!
	}
	logging(log_type, log_level, log_tv, NULL, NULL, log_str, strlen(log_str));

	snprintf(log_str, MAX_LOG_LENGTH, "--------------------------------\n");
	logging(log_type, log_level, log_tv, NULL, NULL, log_str, strlen(log_str));

	// ダンプ文字列領域を破棄
	free(dump_str);

	// 戻る
	return;
}

// --------------------------------
// ログキューイング処理
// --------------------------------
void log_queueing(int from_to, struct EVS_ev_client_t *this_client, struct EVS_ev_pgsql_t *this_pgsql, char *target_buf, int target_len)
{
	struct EVS_ev_message_t         *message_info;                      // メッセージ用構造体ポインタ

	char                            log_str[MAX_LOG_LENGTH];
	
	// メッセージ用構造体ポインタのメモリ領域を確保
	message_info = (struct EVS_ev_message_t *)calloc(1, sizeof(struct EVS_ev_message_t));
	// メモリ領域が確保できなかったら
	if (message_info == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot calloc message_info's memory? errno=%d (%s)\n", __func__, errno, strerror(errno));
		log_output(LOGLEVEL_ERROR,  NULL, log_str, strlen(log_str));
		return;
	}

	// メッセージ情報にメッセージの各種情報をコピー
	message_info->from_to = from_to;                                // メッセージの方向

	// メッセージの方向がLOGLEVEL_MAX以上で、クライアント構造体ポインタとPostgreSQl構造体ポインタがNULLではないなら
	if (from_to > LOGLEVEL_MAX && this_client != NULL && this_pgsql != NULL)
	{
		message_info->client_socket_fd = this_client->socket_fd;        // 接続してきたクライアントのファイルディスクリプタ
		message_info->client_status = this_client->client_status;       // クライアント毎の状態
		message_info->client_ssl_status = this_client->ssl_status;      // クライアント毎のSSL接続状態
		strcpy(message_info->client_addr_str, this_client->addr_str);   // クライアントのアドレス文字列

		message_info->pgsql_socket_fd = this_pgsql->socket_fd;          // 接続してきたクライアントのファイルディスクリプタ
		message_info->pgsql_status = this_pgsql->pgsql_status;          // クライアント毎の状態
		message_info->pgsql_ssl_status = this_pgsql->ssl_status;        // クライアント毎のSSL接続状態
		strcpy(message_info->pgsql_addr_str, this_pgsql->addr_str);     // クライアントのアドレス文字列
	}

	gettimeofday(&message_info->message_tv, NULL);                      // 現在時刻を取得してmessage_info->message_tvに格納

	// 受信したデータ分だけメモリ確保
	message_info->message_ptr = calloc(1, target_len + 1);
	// メモリ領域が確保できなかったら
	if (message_info->message_ptr == NULL)
	{
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot calloc message_info->message_ptr's memory? errno=%d (%s)\n", __func__, errno, strerror(errno));
		log_output(LOGLEVEL_ERROR,  NULL, log_str, strlen(log_str));
		return;
	}
	// 受信したデータをコピー
	memcpy(message_info->message_ptr, target_buf, target_len);

	// --------------------------------
	// テールキュー処理
	// --------------------------------
	// テールキューの最後にこの接続の情報を追加する
	TAILQ_INSERT_TAIL(&EVS_message_tailq, message_info, entries);

	// アイドルイベント開始(メッセージ用キュー処理)
	ev_idle_start(EVS_loop, &idle_message_watcher);

	// 戻る
	return;
}

// --------------------------------
// ログダイレクト出力処理
// --------------------------------
void log_output(int log_level, struct timeval *log_tv, char * logstr, int loglen)
{
	struct timeval                  system_tv;
	struct tm                       *system_tm;
	char                            time_str[MAX_LOG_LENGTH];

	// ログ日時の指定がNULLなら
	if (log_tv == NULL)
	{
		gettimeofday(&system_tv, NULL);    // 現在時刻を取得してsystem_tvに格納．通常のtime_t構造体とsuseconds_tに値が代入される
	}
	// ログ日時の指定があるなら
	else
	{
		memcpy(&system_tv, log_tv, sizeof(struct timeval));
	}

	// ログ日時を文字列に変換
	system_tm = localtime(&system_tv.tv_sec);
	snprintf(time_str, MAX_LOG_LENGTH, "[%d/%02d/%02d %02d:%02d:%02d.%06d] %s: ",     // 現在時刻
		system_tm->tm_year+1900,    // 年
		system_tm->tm_mon+1,        // 月
		system_tm->tm_mday,         // 日
		system_tm->tm_hour,         // 時
		system_tm->tm_min,          // 分
		system_tm->tm_sec,          // 秒
		system_tv.tv_usec,          // マイクロ秒
		loglevel_list[log_level]        // ログレベル
		);

	// デーモンモードではないなら
	if (EVS_config.daemon != 1)
	{
		// 標準出力
		printf("%s %s", time_str, logstr);
	}
	// デーモンモードなら
	else
	{
		// ログファイル名の指定があるのにログファイルが開いていなければ
		if (EVS_config.log_file != NULL && EVS_log_fd == 0)
		{
			// ログファイルを書き込みで開く(ノンブロッキングにするなら「 | O_NONBLOCK」を追加)
			EVS_log_fd = open(EVS_config.log_file, (O_WRONLY | O_CREAT | O_APPEND), (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
		}
		// ログファイルが開けていないなら
		if (EVS_log_fd == 0 || EVS_log_fd == -1)
		{
			// 標準出力
			printf("%s %s", time_str, logstr);
		}
		else
		{
			// ログファイルに出力
			write(EVS_log_fd, time_str, strlen(time_str));
			write(EVS_log_fd, logstr, loglen);
		}
	}

	// 戻る
	return;
}

// --------------------------------
// ログ出力処理
// --------------------------------
// ※ログ出力の時系列をなるべく合わせたい(特にクライアントやPostgreSQLとの接続中)ので、単にログに出力するのではなく、いろいろな引数とともに出力方法を制御する
void logging(int log_type, int from_to, struct timeval *log_tv, struct EVS_ev_client_t *this_client, struct EVS_ev_pgsql_t *this_pgsql, char * log_str, int log_len)
{
	// ログレベル(from_to)が設定値未満なら
	if (from_to < EVS_config.log_level)
	{
		// ログ出力しない
		return;
	}

	// ログモードが0:直接出力(初期化中)か、
	// ログ出力タイプが直接(0:LOG_DIRECT)か、
	if (EVS_log_mode == 0 ||
		 log_type == LOG_DIRECT)
	{
		// ログダイレクト出力処理
		log_output(from_to, log_tv, log_str, log_len);
	}
	// それ以外は
	else
	{
		// ログキューイング処理
		log_queueing(from_to, this_client, this_pgsql, log_str, log_len);
	}

	// 戻る
	return;
}

// --------------------------------
// バイナリHEX変換(PostgreSQLに暗号化パスワードを送信するときには、バイナリをHEXな文字列に変換してあげないといけない)
// --------------------------------
int byte2hex(unsigned char *bindata, unsigned int binlen, char *hexdata)
{
	static const char               *hexchar = "0123456789abcdef";
	unsigned int                    binpos;

	for (binpos = 0; binpos < binlen; binpos++)
	{
		*hexdata = hexchar[ (bindata[binpos] >> 4) & 0x0f ];
		hexdata ++;
		*hexdata = hexchar[ bindata[binpos] & 0x0f ];
		hexdata ++;
	}
	*hexdata = '\0';

	return binpos * 2;
}

// --------------------------------
// 暗号化データ生成(暗号化方式(文字列で"md5", "sha256"など)、暗号対象データ、暗号対象データ長、ソルトデータ、ソルトデータ長、ハッシュ化データ格納ポインタ)
// --------------------------------
int gethashdata(const char *target_type, char *target_data, int target_len, char *target_salt, int salt_len, char *result_data)
{
	char                            log_str[MAX_LOG_LENGTH];

	EVP_MD_CTX                      *mdctx;                             // ダイジェストコンテキスト構造体ポインタ
	const EVP_MD                    *md;                                // EVP_MD構造体ポインタ
	unsigned char                   md_value[EVP_MAX_MD_SIZE];          // ダイジェスト値格納先
	unsigned int                    md_len;                             // ダイジェスト長
	unsigned int                    result_len;                         // HEX変換した後の文字列長(\0は含まれない)

	// 指定されたダイジェスト名によりEVP_MD構造体を取得する
	md = EVP_get_digestbyname(target_type);
	// もしEVP_MD構造体が取得できなかったら
	if (md == NULL)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(): Cannot get EVP_get_digestbyname(%s)!? %s\n", __func__, target_type, ERR_reason_error_string(ERR_get_error()));
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		return -1;
	}

	// 新しいダイジェストコンテキストを取得する
	mdctx = EVP_MD_CTX_new();
	// 指定されたダイジェスト名により取得したEVP_MD構造体を使用するように、ダイジェストコンテキストを設定
	EVP_DigestInit_ex(mdctx, md, NULL);
	// target_dataのtarget_lenバイトのデータを、ダイジェストコンテキストmdctxにハッシュ
	EVP_DigestUpdate(mdctx, target_data, target_len);
	// さらにtarget_saltのsalt_lenバイトのデータを、ダイジェストコンテキストmdctxに追加ハッシュ
	EVP_DigestUpdate(mdctx, target_salt, salt_len);
	// ダイジェスト値を取得しmd_valueに設定(長さはmd_lenに返される)
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	// ダイジェストコンテキストを解放
	EVP_MD_CTX_free(mdctx);

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): md_len=%d\n", __func__, md_len);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// バイナリHEX変換(PostgreSQLに暗号化パスワードを送信するときには、バイナリをHEXな文字列に変換してあげないといけない)
	result_len = byte2hex(md_value, md_len, result_data);

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): result_data=%s (result_len=%d)\n", __func__, result_data, result_len);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	return result_len;
}

// --------------------------------
// データ分割処理(対象データ、対象データ長、セパレータ、セパレータ長、格納配列)
// --------------------------------
int memmemlist(void * target_data, int target_size, void * separator, int separator_size, int list_limit, struct EVS_value_t *result_list)
{
	void                            *target_ptr;
	void                            *value_ptr;
	int                             list_num = 0;

	// 値ポインタを設定する
	value_ptr = target_data;
	// 対象データの先頭から1バイトずつ、セパレータと比較していく
	for (target_ptr = target_data; target_ptr < (target_data + target_size); )
	{
		// 対象データとセパレータとを比較して、合致しないなら
		if (memcmp(target_ptr, separator, separator_size) != 0)
		{
			// 対象データのポインタを1バイトずらす
			target_ptr ++;
			// for()の最初に戻る
			continue;
		}
		// 合致したなら
		// 分割データの先頭ポインタを設定
		result_list[list_num].value_ptr = value_ptr;
		// 分割データの長さを設定
		result_list[list_num].value_len = target_ptr - value_ptr;
		// 対象データのポインタを移動する
		target_ptr += separator_size;
		// 値ポインタを設定する
		value_ptr = target_ptr;
		// 分割データ数を加算
		list_num ++;
		// 分割データの最大数に達したら
		if (list_num >= list_limit)
		{
			// for()を抜ける
			break;
		}
	}
	// 分割データ数が0の場合には
	if (list_num == 0)
	{
		// 0を返す
		return list_num;
	}
	// 分割データの先頭ポインタを設定
	result_list[list_num].value_ptr = value_ptr;
	// 分割データの長さを設定
	result_list[list_num].value_len = target_ptr - value_ptr;
	// 分割出来たデータ数を返す
	return list_num + 1;
}

// --------------------------------
// メイン処理
// --------------------------------
int main (int argc, char *argv[])
{
	int                             result;
	char                            log_str[MAX_LOG_LENGTH];

	// --------------------------------
	// 初期化処理
	// --------------------------------
	result = INIT_all(argc, argv);

	// 処理結果がOK(=0)なら
	if (result == 0)
	{
		// 標準ログに出力
		snprintf(log_str, MAX_LOG_LENGTH, "Start. (log_level=%d)\n", EVS_config.log_level);
		logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));
		// ----------------
		// イベントループ開始(libev Ver4.x以降はev_run() 他にもいくつか変更点あり。flag=0がデフォルトで、ノンブロッキングはEVRUN_NOWAIT=1、一度きりはEVRUN_ONCE=2)
		// ----------------
		ev_run(EVS_loop, 0);
	}

	// --------------------------------
	// 終了処理
	// --------------------------------
	CLOSE_all();
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): CLOSE_all(): Go!\n", __func__);                // daemon(0, 0): を呼ぶ前にログを出力
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// ----------------
	// 作成したイベントループの破棄
	// ----------------
	ev_loop_destroy(EVS_loop);
	snprintf(log_str, MAX_LOG_LENGTH, "%s(): ev_loop_destroy(): Go!\n", __func__);          // daemon(0, 0): を呼ぶ前にログを出力
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// 標準ログに出力
	snprintf(log_str, MAX_LOG_LENGTH, "Stop.\n");
	logging(LOG_QUEUEING, LOGLEVEL_LOG, NULL, NULL, NULL, log_str, strlen(log_str));

	// ログファイル名の領域を最後に解放
	free(EVS_config.log_file);

	return 0;
}
