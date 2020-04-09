﻿// WideTunnel Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// Wt.h
// WideTunnel 全体のヘッダ

#ifndef	WT_H
#define WT_H


//////////////////////////////////////////////////////////////////////
// 
// WideTunnel 内部定数
// 
//////////////////////////////////////////////////////////////////////

// エラーコード一覧
#define	ERR_MACHINE_ALREADY_CONNECTED		201	// すでに接続されている
#define ERR_DEST_MACHINE_NOT_EXISTS			202	// 接続先マシンがインターネット上に存在しない
#define ERR_SSL_X509_UNTRUSTED				203	// 接続先 X509 証明書が信頼できない
#define ERR_SSL_X509_EXPIRED				204	// 接続先 X509 証明書の有効期限切れ
#define ERR_TEMP_ERROR						205	// 一時的なエラー
#define ERR_FUNCTION_NOT_FOUND				206	// 関数が見つからない
#define ERR_PCID_ALREADY_EXISTS				207	// すでに同一の PCID が使用されている
#define ERR_TIMEOUTED						208	// タイムアウト発生
#define ERR_PCID_NOT_FOUND					209	// PCID が見つからない
#define ERR_PCID_RENAME_ERROR				210	// PCID のリネームエラー
#define ERR_SECURITY_ERROR					211	// セキュリティエラー
#define ERR_PCID_INVALID					212	// PCID に使用できない文字が含まれている
#define ERR_PCID_NOT_SPECIFIED				213	// PCID が指定されていない
#define ERR_PCID_TOO_LONG					214	// PCID が長すぎる
#define ERR_SVCNAME_NOT_FOUND				215	// 指定されたサービス名が見つからない
#define ERR_INTERNET_COMM_FAILED			216	// インターネットとの間の通信に失敗した
#define	ERR_NO_INIT_CONFIG					217	// 初期設定が完了していない
#define ERR_NO_GATE_CAN_ACCEPT				218	// 接続を受け付けることができる Gate が存在しない
#define ERR_GATE_CERT_ERROR					219	// Gate 証明書エラー
#define ERR_RECV_URL						220	// URL を受信
#define ERR_PLEASE_WAIT						221	// しばらくお待ちください
#define ERR_RESET_CERT						222	// 証明書をリセットせよ
#define ERR_TOO_MANY_CLIENTS				223	// 接続クライアント数が多すぎる


// SNI 文字列
#define WT_SNI_STRING_V2				"wt_v2"


// ローカルディレクトリの EntryPoint のファイル名
#define LOCAL_ENTRY_POINT_FILENAME		"@EntryPoint.dat"

// ポート番号
#define WT_PORT					443

// データ長
#define WT_SESSION_ID_SIZE		SHA1_SIZE				// セッション ID
#define WT_MSID_SIZE			128						// MSID
#define WT_MAX_BLOCK_SIZE		65536					// 最大ブロックサイズ (予備用)
#define WT_DEFAULT_BLOCK_SIZE	1024					// 標準のブロックサイズ
#define WT_WINDOW_SIZE			(32767)					// ウインドウサイズ
#define WT_SOCKET_WINDOW_SIZE	32767					// ソケットのウインドウサイズ (未使用)
#define WT_PCID_SIZE			32						// PCID

// HTTP 関係
#define	HTTP_WIDE_TARGET			"/widetunnel/start.cgi"
#define	HTTP_WIDE_TARGET2			"/widetunnel/connect.cgi"
#define HTTP_WIDE_TARGET_POSTDATA	"WIDETUNNELCONNECT"

// トンネリング通信関係
#define WT_TUNNEL_TIMEOUT		(30 * 1000)				// トンネル通信のタイムアウト時間
#define WT_TUNNEL_KEEPALIVE		(10 * 1000)				// トンネル通信のキープアライブ時間
#define WT_TUNNEL_USED_EXPIRES	(360 * 1000)			// 同一のトンネル ID を再利用しない間隔

// WPC 通信関係
#define WT_WPC_DEFAULT_ENTRANCE_CACHE_SPAN	(30 * 60 * 1000)	// デフォルトの Entrance URL のキャッシュ時間
#define	WT_GATE_CONNECT_RETRY	1000					// Gate への再接続までの時間

// セッションの種類
#define WT_SESSION_GATE			0						// Gate 上のセッション
#define WT_SESSION_CLIENT		1						// Client 上のセッション
#define WT_SESSION_SERVER		2						// Server 上のセッション

// Initial Pack のサイズ
#define WT_INITIAL_PACK_SIZE	1600

// セッション接続情報キャッシュの有効期限のデフォルト値
#define WT_SESSION_INFO_CACHE_EXPIRES_DEFAULT		(60 * 1000)



//////////////////////////////////////////////////////////////////////
// 
// 内部用ヘッダファイル
// 
//////////////////////////////////////////////////////////////////////

// 型一覧
#include <Cedar/WtType.h>

// WideTunnel Gate
#include <Cedar/WtGate.h>

// WideTunnel Server
#include <Cedar/WtServer.h>

// WideTunnel Client
#include <Cedar/WtClient.h>

// Web Procedure Call
#include <Cedar/WtWpc.h>

// Wide
#include <Cedar/Wide.h>


//////////////////////////////////////////////////////////////////////
// 
// 構造体
// 
//////////////////////////////////////////////////////////////////////

// WideTunnel オブジェクト
struct WT
{
	LOCK *Lock;
	REF *Ref;
	CEDAR *Cedar;					// Cedar
	X *MasterCert;					// マスター証明書
	LIST *SockThreadList;			// ソケットとスレッドのリスト (Gate および Client 用)
	LOCK *EntranceCacheLock;		// Entrance のキャッシュ用ロック
	char EntranceCache[MAX_PATH];	// Entrance URL のキャッシュ
	UINT64 EntranceCacheTimestamp;	// Entrance URL の取得日時
	UINT DefaultEntranceCacheExpireSpan;	// Entrance URL の有効期限
	WIDE *Wide;						// Wide へのポインタ

	// Gate 用
	LISTENER *Listener;				// リスナー
	UINT Port;						// ポート番号
	X *GateCert;					// 証明書
	K *GateKey;						// 秘密鍵
	LIST *SessionList;				// セッションリスト
	UCHAR GateId[SHA1_SIZE];		// ゲートウェイ ID

	// Client / Server / Gate 共通
	char EntranceUrl[MAX_PATH];			// エントランス URL
	char FixedEntranceUrl[MAX_PATH];	// 固定されたエントランス URL
	INTERNET_SETTING *InternetSetting;	// インターネット接続設定
	bool CheckSslTrust;					// SSL 証明書の信頼性を検証するかどうか
};

// スレッドとセッションの組み合わせ
struct SOCKTHREAD
{
	THREAD *Thread;						// スレッド
	SOCK *Sock;							// ソケット
};

// SOCKIO
struct SOCKIO
{
	LOCK *Lock;
	REF *Ref;
	bool Disconnected;					// 切断済みフラグ
	UINT Timeout;						// タイムアウト値
	FIFO *RecvFifo;						// 受信バッファ
	FIFO *SendFifo;						// 送信バッファ
	SOCK_EVENT *SockIoEvent;			// SOCKIO イベント (ソケット使用側が使う)
	SOCK_EVENT *SentNoticeEvent;		// 送信通知イベント (裏側スレッドが使う)
	UINT MaxSendBufferSize;				// 最大送信バッファサイズ
	BUF *SendBuf;						// 送信バッファ
	UINT UserData1, UserData2, UserData3, UserData4;	// ユーザーデータ
	PACK *InitialPack;					// Initial Pack
};

// 以前使用されたトンネル ID の一覧
struct USED_TUNNELID
{
	UINT TunnelId;						// トンネル ID
	UINT64 Expires;						// エントリの有効期限
};


//////////////////////////////////////////////////////////////////////
// 
// Wt.c 内関数プロトタイプ
// 
//////////////////////////////////////////////////////////////////////

WT *NewWt(X *master_cert);
WT *NewWtFromHamcore();
void ReleaseWt(WT *wt);
void CleanupWt(WT *wt);
bool WtIsTrustedCert(WT *wt, X *cert);
LIST *NewSockThreadList();
void AddSockThread(LIST *o, SOCK *s, THREAD *t);
void DelSockThread(LIST *o, SOCK *s);
void FreeSockThreadList(LIST *o);
SOCKIO *NewSockIo(SOCK_EVENT *sent_notice_event, SOCK_EVENT *sockio_event);
void SockIoSetMaxSendBufferSize(SOCKIO *io, UINT size);
void ReleaseSockIo(SOCKIO *io);
void CleanupSockIo(SOCKIO *io);
FIFO *SockIoGetRecvFifo(SOCKIO *io);
FIFO *SockIoGetSendFifo(SOCKIO *io);
void SockIoReleaseFifo(FIFO *fifo);
UINT SockIoSendAsync(SOCKIO *io, void *data, UINT size);
UINT SockIoSend(SOCKIO *io, void *data, UINT size);
bool SockIoSendAll(SOCKIO *io, void *data, UINT size);
void SockIoSendAdd(SOCKIO *io, void *data, UINT size);
bool SockIoSendNow(SOCKIO *io);
UINT SockIoRecvAsync(SOCKIO *io, void *data, UINT size);
UINT SockIoRecv(SOCKIO *io, void *data, UINT size);
bool SockIoRecvAll(SOCKIO *io, void *data, UINT size);
SOCK_EVENT *SockIoGetSockIoEvent(SOCKIO *io);
SOCK_EVENT *SockIoGetSentNoticeEvent(SOCKIO *io);
void SockIoSetIoEvent(SOCKIO *io);
void SockIoReplaceIoEvent(SOCKIO *io, SOCK_EVENT *e);
void SockIoSetSentNoticeEvent(SOCKIO *io);
void SockIoSetTimeout(SOCKIO *io, UINT timeout);
bool SockIoIsConnected(SOCKIO *io);
void SockIoDisconnect(SOCKIO *io);
bool SockIoSendPack(SOCKIO *io, PACK *p);
PACK *SockIoRecvPack(SOCKIO *io);
LIST *WtNewUsedTunnelIdList();
void WtFreeUsedTunnelIdList(LIST *o);
void WtAddUsedTunnelId(LIST *o, UINT tunnel_id, UINT64 expire_span);
void WtDeleteOldUsedTunnelId(LIST *o);
bool WtIsTunnelIdExistsInUsedTunnelIdList(LIST *o, UINT tunnel_id);


#endif	// WT_H
