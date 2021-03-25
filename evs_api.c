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
// ----------------
// PosgreSQL関連
// ----------------
const char  *PgSQL_message_front_str[] = {                                                  // PostgreSQLのメッセージ名称の文字列をテーブル化(フロントエンドからのメッセージ用)
								"",                                                         // 0x00 : NUL
								"",                                                         // 0x01 : SOH
								"",                                                         // 0x02 : STX
								"",                                                         // 0x03 : ETX
								"",                                                         // 0x04 : EOT
								"",                                                         // 0x05 : ENQ
								"",                                                         // 0x06 : ACK
								"",                                                         // 0x07 : BEL
								"",                                                         // 0x08 : BS
								"",                                                         // 0x09 : HT
								"",                                                         // 0x0A : LF
								"",                                                         // 0x0B : VT
								"",                                                         // 0x0C : FF(NP)
								"",                                                         // 0x0D : CR
								"",                                                         // 0x0E : SO
								"",                                                         // 0x0F : SI

								"",                                                         // 0x10 : DLE
								"",                                                         // 0x11 : DC1
								"",                                                         // 0x12 : DC2
								"",                                                         // 0x13 : DC3
								"",                                                         // 0x14 : DC4
								"",                                                         // 0x15 : NAK
								"",                                                         // 0x16 : SYN
								"",                                                         // 0x17 : ETB
								"",                                                         // 0x18 : CAN
								"",                                                         // 0x19 : EM
								"",                                                         // 0x1A : SUB
								"",                                                         // 0x1B : ESC
								"",                                                         // 0x1C : FS
								"",                                                         // 0x1D : GS
								"",                                                         // 0x1E : RS
								"",                                                         // 0x1F : US

								"",                                                         // 0x20 : SP
								"",                                                         // 0x21 : !
								"",                                                         // 0x22 : A
								"",                                                         // 0x23 : #
								"",                                                         // 0x24 : $
								"",                                                         // 0x25 : %
								"",                                                         // 0x26 : &
								"",                                                         // 0x27 : '
								"",                                                         // 0x28 : (
								"",                                                         // 0x29 : )
								"",                                                         // 0x2A : *
								"",                                                         // 0x2B : +
								"",                                                         // 0x2C : ,
								"",                                                         // 0x2D : -
								"",                                                         // 0x2E : .
								"",                                                         // 0x2F : /

								"",                                                         // 0x30 : 0
								"",                                                         // 0x31 : 1
								"",                                                         // 0x32 : 2
								" ",                                                        // 0x33 : 3
								"",                                                         // 0x34 : 4
								"",                                                         // 0x35 : 5
								"",                                                         // 0x36 : 6
								"",                                                         // 0x37 : 7
								"",                                                         // 0x38 : 8
								"",                                                         // 0x39 : 9
								"",                                                         // 0x3A : *
								"",                                                         // 0x3B : ;
								"",                                                         // 0x3C : <
								"",                                                         // 0x3D : =
								"",                                                         // 0x3E : >
								"",                                                         // 0x3F : ?

								"",                                                         // 0x40 : @
								"",                                                         // 0x41 : A
								"Bind",                                                     // 0x42 : B ... Bindコマンド(F)
								"Close",                                                    // 0x43 : C ... Closeコマンド(F)
								"Describe",                                                 // 0x44 : D ... Describeコマンド(F)
								"Execute",                                                  // 0x45 : E ... Executeコマンド(F)
								"FunctionCall",                                             // 0x46 : F ... 関数呼び出し(F)
								"",                                                         // 0x47 : G
								"Flush",                                                    // 0x48 : H ... Flushコマンド(F)
								"",                                                         // 0x49 : I
								"",                                                         // 0x4A : J
								"",                                                         // 0x4B : K
								"",                                                         // 0x4C : L
								"",                                                         // 0x4D : M
								"",                                                         // 0x4E : N
								"",                                                         // 0x4F : O

								"Parse",                                                    // 0x50 : P ... Parseコマンド(F)
								"Query",                                                    // 0x51 : Q ... 簡易問い合わせ(F)
								"",                                                         // 0x52 : R
								"Sync",                                                     // 0x53 : S ... Syncコマンド(F)
								"",                                                         // 0x54 : T
								"",                                                         // 0x55 : U
								"",                                                         // 0x56 : V
								"",                                                         // 0x57 : W
								"Terminate",                                                // 0x58 : X ... 終了(F)
								"",                                                         // 0x59 : Y
								"",                                                         // 0x5A : Z
								"",                                                         // 0x5B : [
								"",                                                         // 0x5C : \ 
								"",                                                         // 0x5D : ]
								"",                                                         // 0x5E : ^
								"",                                                         // 0x5F : _

								"",                                                         // 0x60 : `
								"",                                                         // 0x61 : a
								"",                                                         // 0x62 : b
								"CopyDone",                                                 // 0x63 : c ... COPY完了指示子(F&B)
								"CopyData",                                                 // 0x64 : d ... データのCOPY(F&B)
								"",                                                         // 0x65 : e
								"CopyFail",                                                 // 0x66 : f ... COPY失敗指示子(F)
								"",                                                         // 0x67 : g
								"",                                                         // 0x68 : h
								"",                                                         // 0x69 : i
								"",                                                         // 0x6A : j
								"",                                                         // 0x6B : k
								"",                                                         // 0x6C : l
								"",                                                         // 0x6D : m
								"",                                                         // 0x6E : n
								"",                                                         // 0x6F : o

								"Response...",                                              // 0x70 : p ... パスワード応答(F)/最初のSASL応答(F)/SASL応答(F)/GSSAPIまたはSSPI応答(F) ※厳密なメッセージ種別は、その状況から推論しろと…
								"",                                                         // 0x71 : q
								"",                                                         // 0x72 : r
								"",                                                         // 0x73 : s
								"",                                                         // 0x74 : t
								"",                                                         // 0x75 : u
								"",                                                         // 0x76 : v
								"",                                                         // 0x77 : w
								"",                                                         // 0x78 : x
								"",                                                         // 0x79 : y
								"",                                                         // 0x7A : z
								"",                                                         // 0x7B : {
								"",                                                         // 0x7C : |
								"",                                                         // 0x7D : }
								"",                                                         // 0x7E : ~
								"",                                                         // 0x7F : DEL
};

const char  *PgSQL_message_backend_str[] = {                                                // PostgreSQLのメッセージ名称の文字列をテーブル化(バックエンドからのメッセージ用)
								"",                                                         // 0x00 : NUL
								"",                                                         // 0x01 : SOH
								"",                                                         // 0x02 : STX
								"",                                                         // 0x03 : ETX
								"",                                                         // 0x04 : EOT
								"",                                                         // 0x05 : ENQ
								"",                                                         // 0x06 : ACK
								"",                                                         // 0x07 : BEL
								"",                                                         // 0x08 : BS
								"",                                                         // 0x09 : HT
								"",                                                         // 0x0A : LF
								"",                                                         // 0x0B : VT
								"",                                                         // 0x0C : FF(NP)
								"",                                                         // 0x0D : CR
								"",                                                         // 0x0E : SO
								"",                                                         // 0x0F : SI

								"",                                                         // 0x10 : DLE
								"",                                                         // 0x11 : DC1
								"",                                                         // 0x12 : DC2
								"",                                                         // 0x13 : DC3
								"",                                                         // 0x14 : DC4
								"",                                                         // 0x15 : NAK
								"",                                                         // 0x16 : SYN
								"",                                                         // 0x17 : ETB
								"",                                                         // 0x18 : CAN
								"",                                                         // 0x19 : EM
								"",                                                         // 0x1A : SUB
								"",                                                         // 0x1B : ESC
								"",                                                         // 0x1C : FS
								"",                                                         // 0x1D : GS
								"",                                                         // 0x1E : RS
								"",                                                         // 0x1F : US

								"",                                                         // 0x20 : SP
								"",                                                         // 0x21 : !
								"",                                                         // 0x22 : A
								"",                                                         // 0x23 : #
								"",                                                         // 0x24 : $
								"",                                                         // 0x25 : %
								"",                                                         // 0x26 : &
								"",                                                         // 0x27 : '
								"",                                                         // 0x28 : (
								"",                                                         // 0x29 : )
								"",                                                         // 0x2A : *
								"",                                                         // 0x2B : +
								"",                                                         // 0x2C : ,
								"",                                                         // 0x2D : -
								"",                                                         // 0x2E : .
								"",                                                         // 0x2F : /

								"",                                                         // 0x30 : 0
								"ParseComplete",                                            // 0x31 : 1 ... Parse完了指示子(B)
								"BindComplete",                                             // 0x32 : 2 ... Bind完了指示子(B)
								"CloseComplete ",                                           // 0x33 : 3 ... Close完了指示子(B)
								"",                                                         // 0x34 : 4
								"",                                                         // 0x35 : 5
								"",                                                         // 0x36 : 6
								"",                                                         // 0x37 : 7
								"",                                                         // 0x38 : 8
								"",                                                         // 0x39 : 9
								"",                                                         // 0x3A : *
								"",                                                         // 0x3B : ;
								"",                                                         // 0x3C : <
								"",                                                         // 0x3D : =
								"",                                                         // 0x3E : >
								"",                                                         // 0x3F : ?

								"",                                                         // 0x40 : @
								"NotificationResponse",                                     // 0x41 : A ... 通知応答(B)
								"",                                                         // 0x42 : B
								"CommandComplete",                                          // 0x43 : C ... コマンド完了(B)
								"DataRow",                                                  // 0x44 : D ... データ行(B)
								"ErrorResponse",                                            // 0x45 : E ... エラー(B)
								"FunctionCall",                                             // 0x46 : F
								"CopyInResponse",                                           // 0x47 : G ... Start Copy Inの応答(B)
								"CopyOutResponse",                                          // 0x48 : H ... Start Copy Outの応答(B)
								"EmptyQueryResponse",                                       // 0x49 : I ... 空の問い合わせ文字列に対する応答(B)
								"",                                                         // 0x4A : J
								"BackendKeyData",                                           // 0x4B : K ... 取り消しする際のキーデータ(B)
								"",                                                         // 0x4C : L
								"",                                                         // 0x4D : M
								"NoticeResponse",                                           // 0x4E : N ... 警報(B)
								"",                                                         // 0x4F : O

								"",                                                         // 0x50 : P
								"",                                                         // 0x51 : Q
								"Authentication",                                           // 0x52 : R ... OKか、特定の認証が必要かはメッセージ内容による(B)
								"ParameterStatus",                                          // 0x53 : S ... 実行時パラメータ状態報告(B)
								"RowDescription",                                           // 0x54 : T ... 行の記述(B)
								"",                                                         // 0x55 : U
								"FunctionCallResponse",                                     // 0x56 : V ... 関数呼び出しの結果(B)
								"CopyBothResponse",                                         // 0x57 : W ... Start Copy Bothの応答(B)
								"",                                                         // 0x58 : X
								"",                                                         // 0x59 : Y
								"ReadyForQuery",                                            // 0x5A : Z ... 新しい問い合わせサイクルの準備が整った
								"",                                                         // 0x5B : [
								"",                                                         // 0x5C : \ 
								"",                                                         // 0x5D : ]
								"",                                                         // 0x5E : ^
								"",                                                         // 0x5F : _

								"",                                                         // 0x60 : `
								"",                                                         // 0x61 : a
								"",                                                         // 0x62 : b
								"CopyDone",                                                 // 0x63 : c ... COPY完了指示子(F&B)
								"CopyData",                                                 // 0x64 : d ... データのCOPY(F&B)
								"",                                                         // 0x65 : e
								"",                                                         // 0x66 : f
								"",                                                         // 0x67 : g
								"",                                                         // 0x68 : h
								"",                                                         // 0x69 : i
								"",                                                         // 0x6A : j
								"",                                                         // 0x6B : k
								"",                                                         // 0x6C : l
								"",                                                         // 0x6D : m
								"NoData",                                                   // 0x6E : n ... データなしの指示子(B)
								"",                                                         // 0x6F : o

								"",                                                         // 0x70 : p
								"",                                                         // 0x71 : q
								"",                                                         // 0x72 : r
								"PortalSuspended",                                          // 0x73 : s ... ポータル中断指示子(B)
								"ParameterDescription",                                     // 0x74 : t ... パラメータ記述(B)
								"",                                                         // 0x75 : u
								"NegotiateProtocolVersion",                                 // 0x76 : v ... プロトコルバージョン交渉(B)
								"",                                                         // 0x77 : w
								"",                                                         // 0x78 : x
								"",                                                         // 0x79 : y
								"",                                                         // 0x7A : z
								"",                                                         // 0x7B : {
								"",                                                         // 0x7C : |
								"",                                                         // 0x7D : }
								"",                                                         // 0x7E : ~
								"",                                                         // 0x7F : DEL
};

const char  *PgSQL_client_param_list[] = {                                                  // PostgreSQLの開始メッセージ中の各種設定値名(基本的には受けたメッセージをそのままPostgreSQLに転送するけどね)
								"database",                                                 // 接続したいデータベース名
								"user",                                                     // 接続してきたユーザー名
								"client_encoding",                                          // クライアントが指定してきた文字コード
};

const char  *PgSQL_server_SASL_list[] = {                                                   // PostgreSQLのSASL認証で送られてくるパラメータ
								"r=",                                                       // サーバー側が指定してきたナンス
								"s=",                                                       // サーバー側が指定してきたBASE64エンコードされたソルトキー
								"i=",                                                       // サーバー側が指定してきたイテレーション(反復回数)
								"v=",                                                       // サーバー側が指定してきたベリファイデータ
};

// ----------------------------------------------------------------------
// コード部分
// ----------------------------------------------------------------------
// --------------------------------
// クライアント(psql)関連
// --------------------------------
// evs_api.c に各APIの処理を全部書くと長すぎるので、API毎にファイルを分離する。
// evs_api.c からincludeされることを想定しているので、evs_main.hなどのヘッダファイルはincludeしていない。
#include "evs_api_client.c"

// --------------------------------
// PostgreSQL関連
// --------------------------------
// evs_api.c に各APIの処理を全部書くと長すぎるので、API毎にファイルを分離する。
// evs_api.c からincludeされることを想定しているので、evs_main.hなどのヘッダファイルはincludeしていない。
#include "evs_api_pgsql.c"

// --------------------------------
// PostgreSQLクライアント側処理
// --------------------------------
int API_pgsql_client(struct EVS_ev_client_t *this_client)
{
	int                             api_result = 0;
	char                            log_str[MAX_LOG_LENGTH];

	struct EVS_ev_pgsql_t           *this_pgsql = this_client->pgsql_info;
	struct EVS_db_t                 *db_info = (struct EVS_db_t *)this_pgsql->db_info;

	// とりあえず表示する
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): START! client_status=%d\n", __func__, this_client->socket_fd, this_client->client_status);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// ------------------------------------
	// クライアントからのメッセージ解析
	// ------------------------------------
	// クライアント毎の状態が、0:接続待ちなら
	if (this_client->client_status == 0)
	{
		// クライアント開始メッセージ解析処理を呼び出し(クエリは来ないはず)
		api_result = API_pgsql_client_start(this_client);
		// 正常終了でないなら
		if (api_result != 0)
		{
			// 戻る
			return api_result;
		}
	}
	// クライアント毎の状態が、1:開始メッセージ応答待ちなら
	if (this_client->client_status == 1)
	{
		// ここには来ないはずだが…!?
	}
	// クライアント毎の状態が、2:クエリメッセージ待ちなら
	if (this_client->client_status == 2)
	{
		// クライアントクエリメッセージ解析処理を呼び出し(クエリ以外の場合もあり)
		api_result = API_pgsql_client_query(this_client);
		// 正常終了でないなら
		if (api_result != 0)
		{
			// 戻る
			return api_result;
		}
	}
	// クライアント毎の状態が、3:クエリデータ待ちなら
	if (this_client->client_status == 3)
	{
	}
	
	// 上記以外は
	if (this_client->client_status < 0 ||
		this_client->client_status > 3)
	{
		// エラー
		snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): Illegal Client Status(=%d)!?\n", __func__, this_client->socket_fd, this_client->client_status);
		logging(LOG_DIRECT, LOGLEVEL_ERROR, NULL, NULL, NULL, log_str, strlen(log_str));
		// 戻る
		return -1;
	}

	snprintf(log_str, MAX_LOG_LENGTH, "%s(): END!\n", __func__);
	logging(LOG_QUEUEING, LOGLEVEL_DEBUG, NULL, NULL, NULL, log_str, strlen(log_str));

	// 戻る
	return api_result;
}

// --------------------------------
// API開始処理(クライアント別処理分岐、スレッド生成など)
// --------------------------------
int API_start(struct EVS_ev_client_t *this_client)
{
	int                             api_result;
	char                            log_str[MAX_LOG_LENGTH];

	// とりあえず表示する
	snprintf(log_str, MAX_LOG_LENGTH, "%s(fd=%d): START!\n", __func__, this_client->socket_fd);
	logging(LOG_QUEUEING, LOGLEVEL_INFO, NULL, NULL, NULL, log_str, strlen(log_str));

	// PostgreSQLクライアント側処理を通常呼出
	api_result = API_pgsql_client(this_client);

	// クライアント毎のリクエストで処理時間が変わるので、スレッド化して分散処理をしたほうがいいかと思ったけれど、スレッドを生成すると、クライアントからの接続をとりこぼす事象が発生した。
	// これとは別にHTTP処理について作りこみをしたが、少なくともabでApache(Prefork)との処理速度比較をすると、変にスレッド生成しないのが一番速いという結果がでた。
	// libevとpthreadの関係だと思うけど、深いところまでは追っていないので、調べて教えてくれると嬉しいです。

	// 戻る
	return api_result;
}