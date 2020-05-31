﻿// PacketiX Desktop VPN Source Code
// 
// Copyright (C) 2004-2017 SoftEther Corporation.
// All Rights Reserved.
// 
// http://www.softether.co.jp/
// Author: Daiyuu Nobori

// Desk.h
// PacketiX Desktop VPN ヘッダ

#ifndef	DESK_H
#define DESK_H

//////////////////////////////////////////////////////////////////////
// 
// Desktop VPN 内部定数
// 
//////////////////////////////////////////////////////////////////////

// 機能無効モード (高度なユーザー認証機能、イベントログ機能、syslog 機能が無効になる)
//#define	DESK_DISABLE_NEW_FEATURE



// バージョン情報
#define	DESK_BUILD						CEDAR_BUILD		// ビルド番号
#define DESK_VERSION					CEDAR_VER			// バージョン番号

// EXE の末尾のシグネチャ (これが書いてあれば共有機能強制 OFF 版)
#define	DESK_EXE_DISABLE_SHARE_SIGNATURE	"DisableShare\r\n"
#define	DESK_EXE_DISABLE_SHARE_SIGNATURE_SIZE	14

// 通信関係
#define DS_WAIT_FOR_URDP_SERVER_TIMEOUT	(15 * 1000)	// URDP Server が利用可能になるまでの待機時間
#define DS_PROTOCOL_CONNECTING_TIMEOUT	(3 * 60 * 1000)	// 接続中のプロトコルでのタイムアウト (OTP もあるので 3 分にした)


// ユーザー認証
#define DESK_AUTH_NONE					0		// 認証無し
#define DESK_AUTH_PASSWORD				1		// パスワード認証
#define	DESK_AUTH_USERPASSWORD			CLIENT_AUTHTYPE_PLAIN_PASSWORD	// 2: ユーザー名とパスワードによる認証
#define	DESK_AUTH_CERT					CLIENT_AUTHTYPE_CERT		// 3: 証明書認証
#define DESK_AUTH_SMARTCARD				CLIENT_AUTHTYPE_SECURE		// 4: スマートカード認証

// 提供するサービス
#define DESK_SERVICE_RDP				0		// RDP
#define DESK_SERVICE_VNC				1		// VNC

// エラーコード一覧
#define ERR_DESK_VERSION_DIFF			300		// サービスと設定ツールのバージョンが違う
#define	ERR_DESK_RPC_CONNECT_FAILED		301		// サービスに接続できない
#define	ERR_DESK_RPC_PROTOCOL_ERROR		302		// RPC プロトコルエラー
#define ERR_DESK_URDP_DESKTOP_LOCKED	303		// デスクトップがロックされている
#define ERR_DESK_NOT_ACTIVE				304		// 接続を受け付けていない
#define ERR_DESK_URDP_START_FAILED		306		// URDP の起動に失敗した
#define ERR_DESK_FAILED_TO_CONNECT_PORT	307		// ポートへの接続に失敗した
#define ERR_DESK_LOCALHOST				308		// localhost に対して接続しようとした
#define ERR_DESK_UNKNOWN_AUTH_TYPE		309		// 不明な認証方法
#define	ERR_DESK_LISTENER_OPEN_FAILED	310		// Listen ポートを開けない
#define ERR_DESK_RDP_NOT_ENABLED_XP		311		// RDP が無効である (Windows XP)
#define ERR_DESK_RDP_NOT_ENABLED_VISTA	312		// RDP が無効である (Windows Vista)
#define ERR_DESK_MSTSC_DOWNLOAD_FAILED	313		// mstsc ダウンロード失敗
#define ERR_DESK_MSTSC_INSTALL_FAILED	314		// mstsc インストール失敗
#define ERR_DESK_FILE_IS_NOT_MSTSC		315		// ファイルは mstsc でない
#define ERR_DESK_RDP_NOT_ENABLED_2000	316		// RDP が無効である (Windows 2000)
#define ERR_DESK_BAD_PASSWORD			317		// 入力されたパスワードが間違っている
#define ERR_DESK_PROCESS_EXEC_FAILED	318		// 子プロセス起動失敗
#define	ERR_DESK_DIFF_ADMIN				319		// 管理者ユーザー名が違う
#define	ERR_DESK_DONT_USE_RDP_FILE		320		// .rdp ファイルを指定しないでください
#define	ERR_DESK_RDP_FILE_WRITE_ERROR	321		// .rdp ファイルに書き込めない
#define	ERR_DESK_NEED_WINXP				322		// Windows XP 以降が必要
#define ERR_DESK_PASSWORD_NOT_SET		323		// パスワード未設定
#define ERR_DESK_OTP_INVALID			324		// OTP 間違い
#define ERR_DESK_OTP_ENFORCED_BUT_NO	325		// OTP がポリシー強制なのに設定されていてない
#define ERR_DESK_INSPECTION_AVS_ERROR	326		// 検疫 AVS エラー
#define ERR_DESK_INSPECTION_WU_ERROR	327		// 検疫 Windows Update エラー
#define ERR_DESK_INSPECTION_MAC_ERROR	328		// MAC エラー




// DC 関係パラメータ
#define DC_TUNNEL_QUEUE_SIZE			2		// トンネルキューサイズ
#define DC_TUNNEL_RECONNECT_RETRY_SPAN	(2 * 1000)	// トンネル確立に失敗した場合のリトライ間隔
#define DC_TUNNEL_RECONNECT_RETRY_SPAN_MAX	(3 * 60 * 1000)	// トンネル確立に失敗した場合のリトライ間隔
#define DC_TUNNEL_ESTABLISH_TIMEOUT		(30 * 1000)	// トンネル確立完了まで待機する時間

// DC のイベント
#define DC_EVENT_CONNECTED				1		// 接続した
#define DC_EVENT_URL_RECVED				2		// URL を受信した
#define DC_EVENT_MSG_RECVED				3		// メッセージを受信した

// DC における MSTSC の指定
#define DC_MSTSC_SYSTEM32				0		// system32 内
#define DC_MSTSC_DOWNLOAD				1		// インターネットからダウンロード
#define DC_MSTSC_USERPATH				2		// ユーザーが指定したパス

// MSTSC のバージョン番号
#define DC_MSTSC_VER_XP					1		// Windows XP 版 (5.1 以降)
#define DC_MSTSC_VER_VISTA				2		// Windows Vista 版 (6.0 以降)

// DeskServer のマスク
#define DS_MASK_URDP_CLIENT				1		// User-mode RDP Client
#define DS_MASK_WIN_RDP_NORMAL			2		// 通常の Windows RDP
#define DS_MASK_WIN_RDP_TS				4		// ターミナルサービスの Windows RDP
#define DS_MASK_USER_MODE				8		// ユーザーモード
#define DS_MASK_SERVICE_MODE			16		// サービスモード
#define DS_MASK_POLICY_ENFORCED			32		// ポリシー強制
#define	DS_MASK_OTP_ENABLED				64		// OTP が有効
#define DS_MASK_SUPPORT_WOL_TRIGGER		128		// WOL トリガーをサポート
#define DS_MASK_IS_LIMITED_MODE			256		// 行政情報システム適合モード (Wide Controller が勝手に付ける)



//////////////////////////////////////////////////////////////////////
// 
// 内部用ヘッダファイル
// 
//////////////////////////////////////////////////////////////////////

// 型一覧
#include <Cedar/DeskType.h>

// Desktop VPN Server
#include <Cedar/DS.h>

// Desktop VPN Server RPC
#include <Cedar/DsRpc.h>

// Desktop VPN Client
#include <Cedar/DC.h>

// Desktop VPN Server 設定ツール
#include <Cedar/DG.h>

// Desktop VPN Client GUI
#include <Cedar/DU.h>

// Desktop VPN Setup GUI
#include <Cedar/DI.h>


//////////////////////////////////////////////////////////////////////
// 
// 構造体
// 
//////////////////////////////////////////////////////////////////////

// URDP Server 制御
struct URDP_SERVER
{
	LOCK *Lock;
	UINT Counter;
	void *ProcessHandle;
};


//////////////////////////////////////////////////////////////////////
// 
// Desk.c 内関数プロトタイプ
// 
//////////////////////////////////////////////////////////////////////

bool DeskInitUrdpFiles(wchar_t *dst_dir, bool rudp_server_manifest, bool overwrite);
URDP_SERVER *DeskInitUrdpServer();
void DeskFreeUrdpServer(URDP_SERVER *u);
void DeskStartUrdpServer(URDP_SERVER *u, UINT version);
void DeskStopUrdpServer(URDP_SERVER *u);
void DeskTerminateOldUrdpProcesses(UINT version);
void DeskGetUrdpServerExeName(wchar_t *name, UINT size, UINT version);
bool DeskWaitReadyForUrdpServer();
bool DeskWaitReadyForDeskServerRpc();
void DeskRelay(SOCKIO *io, SOCK *s);
void DeskGetMachineKey(void *data);
void DeskGetAppDataDir(wchar_t *name, UINT name_size);
void DeskGetAppDataDirOld(wchar_t *name, UINT name_size);
bool DeskInstallRudpServerToProgramFilesDir();
void DeskGetRudpServerProgramFilesDir(wchar_t *dir, UINT size);
bool DeskIsUacSettingStrict();
void DeskMitigateUacSetting();
bool DeskCheckUrdpProcessIsRunning();

bool DeskCheckUrdpIsInstalledOnProgramFiles(UINT version);

#endif	// DESK_H


