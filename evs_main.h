// ----------------------------------------------------------------------
// Protocol Analyzer for PostgreSQL -
// Version:
//     Please show evs_main.c.
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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>                                          // 標準入出力関連
#include <unistd.h>                                         // 標準入出力ファイルディスクリプタの型定義とか
#include <stdlib.h>                                         // 標準処理関連
#include <string.h>                                         // 文字列関連
#include <ctype.h>                                          // 文字関連
#include <fcntl.h>                                          // ファイル関連

#include <netdb.h>                                          // ネットワーク・データベース操作関連

#include <sys/queue.h>                                      // リスト・テール(tail)キュー・循環キュー関連
#include <sys/types.h>                                      // データタイプ(型)関連
#include <sys/socket.h>                                     // ソケット関連
#include <sys/ioctl.h>                                      // I/O関連
#include <sys/un.h>                                         // UNIXドメインソケット関連
#include <sys/stat.h>                                       // ステータス関連
#include <sys/time.h>                                       // 日時関連

#include <arpa/inet.h>                                      // アドレス変換関連

#include <netinet/in.h>                                     // IPv4関連
#include <netinet/tcp.h>                                    // TCP関連

#include <openssl/ssl.h>                                    // OpenSSL関連
#include <openssl/err.h>                                    // OpenSSL関連
#include <openssl/crypto.h>                                 // OpenSSL関連

#include <ev.h>                                             // libev関連

#include <errno.h>                                          // エラー番号関連

// --------------------------------
// 定数宣言
// --------------------------------
#define EVS_NAME                "EvServer+PgAnalyzer"
#define EVS_VERSION             "0.1.0"

#define MAX_STRING_LENGTH       1024                        // 設定ファイル中とかの、一行当たりの最大文字数
#define MAX_LOG_LENGTH          1024                        // ログの、一行当たりの最大文字数
#define MAX_MESSAGE_LENGTH      8192                        // ソケット通信時の一回の送受信(recv/send)当たりの最大文字数
#define MAX_SIZE_1K             16384                       // 定数1KB
#define MAX_SIZE_2K             16384                       // 定数2KB
#define MAX_SIZE_4K             16384                       // 定数4KB
#define MAX_SIZE_8K             16384                       // 定数8KB
#define MAX_SIZE_16K            16384                       // 定数16KB
#define MAX_SIZE_32K            32768                       // 定数32KB
#define MAX_SIZE_64K            65536                       // 定数64KB
#define MAX_SIZE_128K           131072                      // 定数128KB

#define MAX_PF_NUM              16                          // 対応するプロトコルファミリーの最大数(PF_KEYまで…実際にはPF_UNIX、PF_INET、PF_INET6しか扱わない)

enum    logtype  {                                          // ログ出力方法
								LOG_DIRECT,
								LOG_QUEUEING,
};

enum    loglevel {                                          // ログレベル
								LOGLEVEL_DEBUG,
								LOGLEVEL_INFO,
								LOGLEVEL_DUMP,
								LOGLEVEL_LOG,
								LOGLEVEL_WARN,
								LOGLEVEL_ERROR,
								LOGLEVEL_MAX,
};

// ----------------
// 以下、個別のAPI関連
// ----------------
#define MAX_RECV_BUF_LENGTH     MAX_SIZE_64K                // クライアントから受信したメッセージを格納するバッファの最大長

enum CLIENT_PARAM_LIST {                                                                    // PostgreSQLでクライアントから送られてくる各種設定値(※相対文字列はPgSQL_client_param_list[])
								CLIENT_DATABASE,                                            // 接続したいデータベース名
								CLIENT_USERNAME,                                            // 接続してきたユーザー名
								CLIENT_ENCODING,                                            // クライアントが指定してきた文字コード

								CLIENT_PARAM_END,                                           // 設定値の最後(これをfor分の最後までの判定などに使えばよい)
};

// --------------------------------
// 型宣言
// --------------------------------
struct EVS_value_t {                                        // 設定値のポインタとその長さの構造体
	char            *value_ptr;                             // 設定値の先頭ポインタ
	int             value_len;                              // 設定値の長さ
};

struct EVS_config_t {                                       // 各種設定用構造体
	int             daemon;                                 // デーモン化(0:フロントプロセス、1:デーモン化)

	char            *pid_file;                              // PIDファイル名のフルパス
	char            *log_file;                              // ログファイル名のフルパス
	int             log_level;                              // ログに出力するレベル(0:DEBUG, 1:INFO, 2:WARN, 3:ERROR)

	char            *domain_socketfile;                     // UNIXドメインソケットファイル名のフルパス

	int             ssl_support;                            // SSL/TLS対応(0:非対応、1:対応)
	char            *ssl_ca_file;                           // サーバー証明書(PEM)CAファイルのフルパス
	char            *ssl_cert_file;                         // サーバー証明書(PEM)CERTファイルのフルパス
	char            *ssl_key_file;                          // サーバー証明書(PEM)KEYファイルのフルパス

	ev_tstamp       timer_checkintval;                      // タイマーイベント確認間隔(秒)

	int             nocommunication_check;                  // 無通信タイムアウトチェック(0:無効、1:有効)
	ev_tstamp       nocommunication_timeout;                // 無通信タイムアウト(秒)
	
	int             keepalive;                              // KeepAlive(0:無効、1:有効)
	int             keepalive_idletime;                     // KeepAlive Idle(秒)
	int             keepalive_intval;                       // KeepAlive Interval(秒)
	int             keepalive_probes;                       // KeepAlive Probes(回数)
};

struct EVS_port_t {                                         // ポート別設定用構造体
	unsigned short  port;                                   // ポート番号(1～65535)
	int             ipv4;                                   // IPv4フラグ(0:OFF、1:ON)
	int             ipv6;                                   // IPv4フラグ(0:OFF、1:ON)
	int             ssl;                                    // SSL/TLSフラグ(0:OFF、1:ON)
	TAILQ_ENTRY (EVS_port_t) entries;                       // 次のTAILQ構造体への接続 → man3/queue.3.html
};

struct EVS_db_t {                                           // データベース別設定用構造体
	char            database[64];                           // データベース名(PostgreSQLではデータベース名は最大63バイト)
	char            username[32];                           // ユーザー名(PostgreSQLではデータベース名は最大20バイト)
	char            password[32];                           // パスワード(PostgreSQLではデータベース名は最大30バイト)
	char            hostname[128];                          // ホスト名
	char            servicename[16];                        // パスワード(PostgreSQLではデータベース名は最大30バイト)
	unsigned short  port;                                   // ポート番号(1～65535)
	TAILQ_ENTRY (EVS_db_t) entries;                         // 次のTAILQ構造体への接続 → man3/queue.3.html
};

struct EVS_ev_server_t {                                    // コールバック関数内でソケットのファイルディスクリプタも知りたいので拡張した構造体を宣言する、こちらはサーバー用
	ev_io           io_watcher;                             // libevのev_io、これをev_io_init()＆ev_io_start()に渡す
	ev_tstamp       last_activity;                          // 最終アクティブ日時(監視対象が最後にアクティブとなった=タイマー更新した日時)
	int             socket_fd;                              // socket_fd、コールバック関数内でstruct ev_io*で渡される変数のポインタをEVS_ev_server_t*に型変換することで参照する
	int             ssl_support;                            // SSL/TLS対応状態(0:非対応、1:SSL/TLS対応)
	union {                                                 // ソケットアドレス構造体の共用体
		struct sockaddr_in  sa_ipv4;                        //  IPv4用ソケットアドレス構造体
		struct sockaddr_in6 sa_ipv6;                        //  IPv6用ソケットアドレス構造体
		struct sockaddr_un  sa_un;                          //  UNIXドメイン用ソケットアドレス構造体
		struct sockaddr     sa;                             //  ソケットアドレス構造体
	} socket_address;
	TAILQ_ENTRY (EVS_ev_server_t) entries;                  // 次のTAILQ構造体への接続 → man3/queue.3.html
};

struct EVS_ev_pgsql_t {                                     // PostgreSQL用構造体
	ev_io           io_watcher;                             // libevのev_io、これをev_io_init()＆ev_io_start()に渡す
	ev_tstamp       last_activity;                          // 最終アクティブ日時(PostgreSQLとのやり取りが最後にアクティブとなった日時)
	int             socket_fd;                              // PostgreSQLに接続した際のファイルディスクリプタ
	int             pgsql_status;                           // PostgreSQLへの接続状態(0:未接続、1:接続開始、2:接続中、3:レスポンスデータ待ちなど)
	int             ssl_status;                             // SSL接続状態(0:非SSL/SSL接続前、1:SSLハンドシェイク中、2:SSL接続中)
	SSL_CTX         *ctx;                                   // SSL設定情報
	SSL             *ssl;                                   // SSL接続情報
	union {                                                 // ソケットアドレス構造体の共用体
		struct addrinfo     pgsql_addrinfo;                 //  INET用ソケットアドレス構造体
		struct sockaddr_un  sa_un;                          //  UNIXドメイン用ソケットアドレス構造体
		struct sockaddr     sa;                             //  ソケットアドレス構造体
	} socket_address;
	char            addr_str[64];                           // アドレスを文字列として格納する(UNIX DOMAIN SOCKET/xxx.xxx.xxx.xxx(IPv4)/xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx(IPv6))
	void            *client_info;                           // クライアント別拡張構造体へのポインタ
	void            *db_info;                               // データベース別構造体へのポインタ
	int             recv_len;                               // PostgreSQLから受信したメッセージ長
	char            recv_buf[MAX_RECV_BUF_LENGTH];          // PostgreSQLから受信したメッセージ
	TAILQ_ENTRY (EVS_ev_pgsql_t) entries;                   // 次のTAILQ構造体への接続 → man3/queue.3.html
};

struct EVS_ev_client_t {                                    // コールバック関数内でソケットのファイルディスクリプタも知りたいので拡張した構造体を宣言する、こちらはクライアント用
	ev_io           io_watcher;                             // libevのev_io、これをev_io_init()＆ev_io_start()に渡す
	ev_tstamp       last_activity;                          // 最終アクティブ日時(監視対象が最後にアクティブとなった=タイマー更新した日時)
	int             socket_fd;                              // 接続してきたクライアントのファイルディスクリプタ
	int             ssl_support;                            // SSL/TLS対応状態(0:非対応、1:SSL/TLS対応)
	int             client_status;                          // クライアント毎の状態(0:接続待ち、1:開始メッセージ応答待ち、2:クエリメッセージ待ち、3:クエリデータ待ち、など)
	int             ssl_status;                             // SSL接続状態(0:非SSL/SSL接続前、1:SSLハンドシェイク中、2:SSL接続中)
	SSL             *ssl;                                   // SSL接続情報
/*
	union {                                                 // ソケットアドレス構造体の共用体
		struct sockaddr_in  sa_ipv4;                        //  IPv4用ソケットアドレス構造体
		struct sockaddr_in6 sa_ipv6;                        //  IPv6用ソケットアドレス構造体
		struct sockaddr_un  sa_un;                          //  UNIXドメイン用ソケットアドレス構造体
		struct sockaddr     sa;                             //  ソケットアドレス構造体
	} socket_address;
*/
	char            addr_str[64];                           // アドレスを文字列として格納する(UNIX DOMAIN SOCKET/xxx.xxx.xxx.xxx(IPv4)/xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx(IPv6))
	void            *pgsql_info;                            // クライアント毎のPostgreSQL用構造体ポインタ
	int             recv_len;                               // クライアントから受信したメッセージ長
	char            recv_buf[MAX_RECV_BUF_LENGTH];          // クライアントから受信したメッセージ
	char            param_buf[MAX_STRING_LENGTH];           // 各クライアントに必要な各種設定値用バッファ(ユーザー名、データベース名、文字エンコーディングなど…実際には128バイトもいらない)
	char            *param_info[CLIENT_PARAM_END];          // 各種設定値ポインタの配列(各種設定値のparam_buf内のポインタを示す)
	TAILQ_ENTRY (EVS_ev_client_t) entries;                  // 次のTAILQ構造体への接続 → man3/queue.3.html
};

struct EVS_ev_message_t {                                   // メッセージ用構造体
	unsigned int    MID;                                    // メッセージID(TBD)
	int             from_to;                                // メッセージの方向(LOGLEVEL_MAX以下:そのままログに出力, 101:Client->PgAnalyzer, 102:PgAnalyzer->Client, 111:PgAnalyzer->PostgreSQL, 112:PostgreSQL->PgAnalyzer)
	int             client_socket_fd;                       // PostgreSQLに接続した際のファイルディスクリプタ
	int             client_status;                          // クライアント毎の状態(0:接続待ち、1:開始メッセージ応答待ち、2:クエリメッセージ待ち、3:クエリデータ待ち、など)
	int             client_ssl_status;                      // SSL接続状態(0:非SSL/SSL接続前、1:SSLハンドシェイク中、2:SSL接続中)
	char            client_addr_str[64];                    // アドレスを文字列として格納する(UNIX DOMAIN SOCKET/xxx.xxx.xxx.xxx(IPv4)/xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx(IPv6))
	int             pgsql_socket_fd;                        // PostgreSQLに接続した際のファイルディスクリプタ
	int             pgsql_status;                           // PostgreSQLへの接続状態(0:未接続、1:接続開始、2:接続中、3:レスポンスデータ待ちなど)
	int             pgsql_ssl_status;                       // SSL接続状態(0:非SSL/SSL接続前、1:SSLハンドシェイク中、2:SSL接続中)
	char            pgsql_addr_str[64];                     // アドレスを文字列として格納する(UNIX DOMAIN SOCKET/xxx.xxx.xxx.xxx(IPv4)/xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx(IPv6))
	struct timeval  message_tv;                             // メッセージを受信した秒・マイクロ秒の構造体
	void            *message_ptr;                           // malloc&memcpyしたメッセージへのポインタ
	unsigned int    message_len;                            // malloc&memcpyしたメッセージの長さ
	TAILQ_ENTRY (EVS_ev_message_t) entries;                 // 次のTAILQ構造体への接続 → man3/queue.3.html
};

struct EVS_timer_t {                                        // タイマー別構造体
	ev_tstamp       timeout;                                // タイムアウト秒(ev_now + タイムアウト時間)
	void            *target;                                // タイムアウトに必要な構造体のポインタ
	TAILQ_ENTRY (EVS_timer_t) entries;                      // 次のTAILQ構造体への接続 → man3/queue.3.html
};

// --------------------------------
// 変数宣言
// --------------------------------
// ----------------
// 設定値関連
// ----------------
extern struct EVS_config_t              EVS_config;                     // システム設定値

// ----------------
// libev 関連
// ----------------
extern ev_idle                          idle_message_watcher;           // アイドルオブジェクト(メッセージ用。なにもイベントがないときに呼ばれて、メッセージ解析してログ出力などする)
extern ev_io                            stdin_watcher;                  // I/O監視オブジェクト
extern ev_timer                         timeout_watcher;                // タイマーオブジェクト
extern ev_signal                        signal_watcher_sighup;          // シグナルオブジェクト(シグナルごとにウォッチャーを分けないといけない)
extern ev_signal                        signal_watcher_sigint;          // シグナルオブジェクト(シグナルごとにウォッチャーを分けないといけない)
extern ev_signal                        signal_watcher_sigterm;         // シグナルオブジェクト(シグナルごとにウォッチャーを分けないといけない)

extern struct ev_loop                   *EVS_loop;                      // イベントループ

extern struct EVS_ev_server_t           *server_watcher[];              // ev_io＋ソケットファイルディスクリプタ、ソケットアドレスなどの拡張構造体

// ----------------
// ソケット関連
// ----------------
extern const char                       *pf_name_list[];                // プロトコルファミリーの一部の名称を文字列テーブル化
extern int                              EVS_connect_num;                // クライアント接続数

// ----------------
// SSL/TLS関連
// ----------------
extern SSL_CTX                          *EVS_ctx;                       // SSL設定情報

// ----------------
// その他の変数
// ----------------
extern const char                       *loglevel_list[];               // ログレベル文字列テーブル
extern int                              EVS_log_fd;                     // ログファイルディスクリプタ
extern int                              EVS_log_mode;                   // ログモード(0:直接出力、1:キューイング)

// ----------------
// 以下、個別のAPI関連
// ----------------

// ----------------------------------------------------------------------
// コード部分
// ----------------------------------------------------------------------
// --------------------------------
// プロトタイプ宣言
// --------------------------------
extern char *getdumpstr(void *, int);                                   // ダンプ文字列生成処理
extern void dump2log(int, int, struct timeval *, void *, int);          // ダンプ出力
extern void log_queueing(int, struct EVS_ev_client_t *, struct EVS_ev_pgsql_t *, char *, int);                          // ログキューイング処理
extern void log_output(int, struct timeval *, char *, int);                                                             // ログダイレクト出力処理
extern void logging(int, int, struct timeval *, struct EVS_ev_client_t *, struct EVS_ev_pgsql_t *, char * , int);       // ログ出力処理
extern int gethashdata(const char *, char *, int , char *, int , char *);   // 暗号化データ生成(暗号化方式(文字列で"md5", "sha256"など)、暗号対象データ、暗号対象データ長、ソルトデータ、ソルトデータ長、ハッシュ化データ格納ポインタ)
extern int memmemlist(void *, int, void *, int, int, struct EVS_value_t *); // データ分割処理(対象データ、対象データ長、セパレータ、セパレータ長、格納配列)

extern int INIT_all(int, char *[]);                                     // 初期化処理

extern void CB_accept_SSL(struct EVS_ev_client_t *);                    // SSL接続情報生成＆ファイルディスクリプタ紐づけ ←PostgreSQLは非暗号化から暗号化通信に移行するため

extern void CLOSE_pgsql(struct ev_loop *, struct ev_io *, int);         // PostgreSQL接続終了処理
extern void CLOSE_client(struct ev_loop *, struct ev_io *, int);        // クライアント接続終了処理
extern int CLOSE_all(void);                                             // 終了処理

extern int API_pgsql_client_message(struct EVS_ev_message_t *);         // クライアントクエリメッセージ解析処理
extern int API_pgsql_message_decodequeryresponse(struct EVS_ev_message_t *, char *, unsigned int);      // PostgreSQL側各種クエリレスポンス解析処理
extern int API_pgsql_server_message(struct EVS_ev_message_t *);         // PostgreSQL側メッセージ処理

extern int API_pgsql_server_send(struct EVS_ev_pgsql_t *, unsigned char *, int );   // PostgreSQL送信処理
extern int API_start(struct EVS_ev_client_t *);                         // API開始処理(クライアント別処理分岐、スレッド生成など)
extern int API_pgsql_server_start(struct EVS_ev_client_t *);            // サーバー接続開始処理
extern int API_pgsql_SSLHandshake(struct EVS_ev_pgsql_t *);             // PostgreSQL SSLハンドシェイク処理
extern int API_pgsql_send_StartupMessage(struct EVS_ev_pgsql_t *);      // PostgreSQL StartupMessage処理 (※この関数を呼ぶ時には、this_client->param_infoに完璧なデータが入っている前提)
extern int API_pgsql_send_PasswordMessageMD5(struct EVS_ev_pgsql_t *);  // PostgreSQL PasswordMessage(MD5)処理

// ----------------
// テールキュー関連
// ----------------
TAILQ_HEAD(EVS_port_tailq_head, EVS_port_t)         EVS_port_tailq;     // ポート用TAILQ_HEAD構造体 → man3/queue.3.html
TAILQ_HEAD(EVS_db_tailq_head, EVS_db_t)             EVS_db_tailq;       // データベース用TAILQ_HEAD構造体 → man3/queue.3.html
TAILQ_HEAD(EVS_server_tailq_head, EVS_ev_server_t)  EVS_server_tailq;   // サーバー用TAILQ_HEAD構造体 → man3/queue.3.html
TAILQ_HEAD(EVS_client_tailq_head, EVS_ev_client_t)  EVS_client_tailq;   // クライアント用TAILQ_HEAD構造体 → man3/queue.3.html
TAILQ_HEAD(EVS_pgsql_tailq_head, EVS_ev_pgsql_t)    EVS_pgsql_tailq;    // PostgreSQL用TAILQ_HEAD構造体 → man3/queue.3.html
TAILQ_HEAD(EVS_message_head, EVS_ev_message_t)      EVS_message_tailq;  // メッセージ用TAILQ_HEAD構造体 → man3/queue.3.html
TAILQ_HEAD(EVS_timer_tailq_head, EVS_timer_t)       EVS_timer_tailq;    // タイマー用TAILQ_HEAD構造体 → man3/queue.3.html
