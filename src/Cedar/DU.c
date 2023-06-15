// IPA-DN-ThinLib Library Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-ThinLib Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA, NTT-EAST, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. IPA AND NTT-EAST HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


// DU.c
// シン・テレワークシステム クライアント GUI

// Build 8600

#include <GlobalConst.h>

#ifdef	_WIN32

#define	SM_C
#define	CM_C
#define	NM_C
#define	DG_C
#define DU_C

#define	_WIN32_IE			0x0600
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#define NTDDI_VERSION NTDDI_WIN7
#include <winsock2.h>
#include <Iphlpapi.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <fixed_Fwpmu.h>
#include <fixed_Fwpmtypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Psapi.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include <Cedar/CMInner.h>
#include <Cedar/SMInner.h>
#include <Cedar/NMInner.h>
#include <Cedar/EMInner.h>
#include <Cedar/Wt.h>
#include <Cedar/Desk.h>
#include "DG_Inner.h"
#include "DU_Inner.h"
#include "../PenCore/resource.h"


// For WFP
// API function
typedef struct DU_WFP_FUNCTIONS
{
	DWORD (WINAPI *FwpmEngineOpen0)(
		IN OPTIONAL const wchar_t* serverName,
		IN UINT32 authnService,
		IN OPTIONAL SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
		IN OPTIONAL const FWPM_SESSION0* session,
		OUT HANDLE* engineHandle
		);

	DWORD (WINAPI *FwpmEngineClose0)(IN HANDLE engineHandle);

	void (WINAPI *FwpmFreeMemory0)(IN OUT void** p);

	DWORD (WINAPI *FwpmFilterAdd0)(
		IN HANDLE engineHandle,
		IN const FWPM_FILTER0* filter,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd,
		OUT OPTIONAL UINT64* id
		);

	DWORD (WINAPI *IPsecSaContextCreate0)(
		IN HANDLE engineHandle,
		IN const IPSEC_TRAFFIC0* outboundTraffic,
		OUT OPTIONAL UINT64* inboundFilterId,
		OUT UINT64* id
		);

	DWORD (WINAPI *IPsecSaContextGetSpi0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_GETSPI0* getSpi,
		OUT IPSEC_SA_SPI* inboundSpi
		);

	DWORD (WINAPI *IPsecSaContextAddInbound0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_SA_BUNDLE0* inboundBundle
		);

	DWORD (WINAPI *IPsecSaContextAddOutbound0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_SA_BUNDLE0* outboundBundle
		);

	DWORD (WINAPI *FwpmCalloutAdd0)(
		IN HANDLE engineHandle,
		IN const FWPM_CALLOUT0* callout,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd,
		OUT OPTIONAL UINT32* id
		);

	DWORD (WINAPI *FwpmSubLayerAdd0)(
			IN HANDLE engineHandle,
			IN const FWPM_SUBLAYER0 *subLayer,
			IN OPTIONAL PSECURITY_DESCRIPTOR sd
		);

	DWORD (WINAPI *FwpmProviderAdd0)(
			IN HANDLE engineHandle,
			IN const FWPM_PROVIDER0 *provider,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd
		);

	DWORD (WINAPI *FwpmGetAppIdFromFileName0)(
			IN PCWSTR fileName,
			OUT FWP_BYTE_BLOB **appId
		);

	DWORD
		(WINAPI *FwpmNetEventCreateEnumHandle0)(
			__in HANDLE engineHandle,
			__in_opt const FWPM_NET_EVENT_ENUM_TEMPLATE0 *enumTemplate,
			__out HANDLE *enumHandle
		);

	DWORD
	(WINAPI *FwpmNetEventEnum0)(
		__in HANDLE engineHandle,
		__in HANDLE enumHandle,
		__in UINT32 numEntriesRequested,
		__deref_out_ecount(*numEntriesReturned) FWPM_NET_EVENT1 ***entries,
		__out UINT32 *numEntriesReturned
		);

	DWORD
		(WINAPI *FwpmNetEventEnum1)(
			__in HANDLE engineHandle,
			__in HANDLE enumHandle,
			__in UINT32 numEntriesRequested,
			__deref_out_ecount(*numEntriesReturned) FWPM_NET_EVENT1 ***entries,
			__out UINT32 *numEntriesReturned
		);

	DWORD
	(WINAPI *FwpmNetEventEnum2)(
		__in HANDLE engineHandle,
		__in HANDLE enumHandle,
		__in UINT32 numEntriesRequested,
		__deref_out_ecount(*numEntriesReturned) FWPM_NET_EVENT1 ***entries,
		__out UINT32 *numEntriesReturned
		);

	DWORD
	(WINAPI *FwpmNetEventEnum3)(
		__in HANDLE engineHandle,
		__in HANDLE enumHandle,
		__in UINT32 numEntriesRequested,
		__deref_out_ecount(*numEntriesReturned) FWPM_NET_EVENT1 ***entries,
		__out UINT32 *numEntriesReturned
		);

	DWORD
	(WINAPI *FwpmNetEventEnum4)(
		__in HANDLE engineHandle,
		__in HANDLE enumHandle,
		__in UINT32 numEntriesRequested,
		__deref_out_ecount(*numEntriesReturned) FWPM_NET_EVENT1 ***entries,
		__out UINT32 *numEntriesReturned
		);

	DWORD
	(WINAPI *FwpmNetEventEnum5)(
		__in HANDLE engineHandle,
		__in HANDLE enumHandle,
		__in UINT32 numEntriesRequested,
		__deref_out_ecount(*numEntriesReturned) FWPM_NET_EVENT1 ***entries,
		__out UINT32 *numEntriesReturned
		);

	DWORD
		(WINAPI *FwpmNetEventDestroyEnumHandle0)(
			__in HANDLE engineHandle,
			__inout HANDLE enumHandle
		);

	DWORD
		(WINAPI *FwpmEngineGetOption0)(
			__in HANDLE engineHandle,
			__in FWPM_ENGINE_OPTION option,
			__deref_out FWP_VALUE0 **value
		);

	DWORD
		(WINAPI *FwpmEngineSetOption0)(
			__in HANDLE engineHandle,
			__in FWPM_ENGINE_OPTION option,
			__in const FWP_VALUE0 *newValue
		);

	DWORD
		(WINAPI *FwpmNetEventSubscribe0)(
			__in HANDLE engineHandle,
			__in const FWPM_NET_EVENT_SUBSCRIPTION0 *subscription,
			__in FWPM_NET_EVENT_CALLBACK0 callback,
			__in_opt void *context,
			__out HANDLE *eventsHandle
		);

	DWORD
		(WINAPI *FwpmNetEventUnsubscribe0)(
			__in HANDLE engineHandle,
			__inout HANDLE eventsHandle
		);


	DWORD
		(WINAPI *FwpmLayerGetByKey0)(
			__in HANDLE engineHandle,
			__in const GUID *key,
			__deref_out FWPM_LAYER0 **layer
		);

} DU_WFP_FUNCTIONS;

typedef struct DU_GOV_FW1_DATA
{
	bool Mandate;
	bool ClickOnce;
} DU_GOV_FW1_DATA;

static DU_WFP_FUNCTIONS *du_wfp_api = NULL;
static HINSTANCE du_wfp_dll = NULL;

bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str);

// 完全閉域化ファイアウォール起動選択画面
bool DuGovFw1Main(bool mandate)
{
	DU_GOV_FW1_DATA t;

	Zero(&t, sizeof(t));
	t.Mandate = mandate;

	// すでに起動しているかどうか調べる
	if (IsSingleInstanceExists(DU_GOV_FW2_SINGLE_INSTANCE_NAME, false))
	{
		// すでに起動しているので何もしない
		return true;
	}

	// ダイアログを表示する
	return Dialog(NULL, D_DU_GOVFW1, DuGovFw1DlgProc, &t);
}

// 完全閉域化ファイアウォール起動選択画面プロシージャ
UINT DuGovFw1DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_GOV_FW1_DATA *t = (DU_GOV_FW1_DATA *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SHIELD);
		DlgFont(hWnd, S_BOLD, 11, true);
		DlgFont(hWnd, S_BOLD2, 0, true);
		DlgFont(hWnd, IDOK, 10, true);
		DlgFont(hWnd, IDCANCEL, 10, false);

		if (t->Mandate)
		{
			SetText(hWnd, IDCANCEL, _UU("DU_GOV_FW_MANDATE_CLOSE_BUTTON"));
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			{
				wchar_t *exe = MsGetExeFileNameW();
				wchar_t *arg = L"/govfw";
				void *handle = NULL;

				if (t->ClickOnce)
				{
					break;
				}

				// for debug
				//exe = L"C:\\git\\IPA-DNP-DeskVPN\\src\\bin\\ThinClient.exe";

				if (MsExecuteEx3W(exe, arg, &handle, true, false))
				{
					// Single instance が生成されるかプロセスが終了するまで待機する
					UINT64 now = Tick64();
					UINT64 giveup = now + 30000ULL;
					bool ok = false;

					t->ClickOnce = true;

					while (true)
					{
						now = Tick64();
						if (now >= giveup)
						{
							break;
						}

						if (IsSingleInstanceExists(DU_GOV_FW2_SINGLE_INSTANCE_NAME, false))
						{
							ok = true;
							break;
						}

						if (MsWaitProcessExitWithTimeoutEx(handle, 100, true))
						{
							break;
						}
					}

					MsCloseHandle(handle);

					EndDialog(hWnd, ok);
				}
			}
			break;

		case IDCANCEL:
			if (t->Mandate)
			{
				if (MsgBox(hWnd, MB_YESNO | MB_DEFBUTTON2 | MB_ICONEXCLAMATION, _UU("DU_GOV_FW_MANDATE_MSG")) == IDNO)
				{
					break;
				}
			}

			Close(hWnd);
			break;
		}

		break;

	case WM_CLOSE:

		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 完全閉域化ファイアウォールのメイン処理
void DuGovFw2Main()
{
	void *h = NULL;
	INSTANCE *inst;

	if (MsIsAdmin() == false)
	{
		return;
	}
	
	inst = NewSingleInstance(DU_GOV_FW2_SINGLE_INSTANCE_NAME);

	if (inst == NULL)
	{
		return;
	}

	h = DuStartApplyWhiteListRules();

	if (h != NULL)
	{
		Dialog(NULL, D_DU_GOVFW2, DuGovFw2DlgProc, NULL);

		DuStopApplyWhiteListRules(h);
	}

	FreeSingleInstance(inst);

	return;
}

// 完全閉域化ファイアウォール
UINT DuGovFw2DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_LANG_JAPANESE);
		DlgFont(hWnd, S_BOLD, 11, true);
		//DlgFont(hWnd, S_BOLD2, 0, true);
		DlgFont(hWnd, IDCANCEL, 10, true);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			if (MsgBox(hWnd, MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION, _UU("DU_GOV_FW_CLOSE_MSG")) == IDYES)
			{
				Close(hWnd);
			}
			break;
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// WoL ダイアログ初期化
void DuWoLDlgInit(HWND hWnd, DU_MAIN *m)
{
	UINT i;
	LIST *c;
	HFONT h;
	if (hWnd == NULL || m == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_NIC_ONLINE);

	DlgFont(hWnd, IDOK, 0, true);

	h = GetFont("Arial", 10, false, false, false, false);
	SetFont(hWnd, C_PCID, h);
	SetFont(hWnd, C_PCID2, h);

	// Candidate
	c = m->Du->Dc->Candidate;
	for (i = 0;i < LIST_NUM(c);i++)
	{
		CANDIDATE *item = LIST_DATA(c, i);

		if (UniIsEmptyStr(item->Str) == false)
		{
			CbAddStr(hWnd, C_PCID, item->Str, 0);
		}
	}
	CbSetHeight(hWnd, C_PCID, 20);

	// Candidate WoL
	c = m->Du->Dc->CandidateWoL;
	for (i = 0;i < LIST_NUM(c);i++)
	{
		CANDIDATE *item = LIST_DATA(c, i);

		if (UniIsEmptyStr(item->Str) == false)
		{
			CbAddStr(hWnd, C_PCID2, item->Str, 0);
		}
	}
	CbSetHeight(hWnd, C_PCID2, 20);
}

// WoL コントロール有効 / 無効変更
void DuWoLSetControlEnable(HWND hWnd, bool b)
{
	SetEnable(hWnd, C_PCID, b);
	SetEnable(hWnd, C_PCID2, b);
	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, IDCANCEL, b);

	if (b)
	{
		EnableClose(hWnd);
	}
	else
	{
		DisableClose(hWnd);
	}

	DoEvents(hWnd);
}

// WoL 実行
bool DuWoLDlgOnOk(HWND hWnd, DU_MAIN *m)
{
	char pcid[MAX_PATH];
	char pcid2[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	bool ret = false;
	UINT err = ERR_NO_ERROR;
	if (hWnd == NULL || m == NULL)
	{
		return false;
	}

	GetTxtA(hWnd, C_PCID, pcid, sizeof(pcid));
	Trim(pcid);
	GetTxtA(hWnd, C_PCID2, pcid2, sizeof(pcid2));
	Trim(pcid2);

	if (IsEmptyStr(pcid))
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("DU_WOL_TARGET_EMPTY"));
		Focus(hWnd, C_PCID);
		return false;
	}

	if (IsEmptyStr(pcid2))
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("DU_WOL_TRIGGER_EMPTY"));
		Focus(hWnd, C_PCID2);
		return false;
	}

	if (StrCmpi(pcid, pcid2) == 0 && DcGetDebugFlag() == false)
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("DU_WOL_TARGET_IS_TRIGGER"));
		Focus(hWnd, C_PCID);
		return false;
	}

	// Target
	StrToUni(tmp, sizeof(tmp), pcid);
	AddCandidate(m->Du->Dc->Candidate, tmp, DU_CANDIDATE_MAX);
	Sort(m->Du->Dc->Candidate);

	// Trigger
	StrToUni(tmp, sizeof(tmp), pcid2);
	AddCandidate(m->Du->Dc->CandidateWoL, tmp, DU_CANDIDATE_MAX);
	Sort(m->Du->Dc->CandidateWoL);

	DcSaveConfig(m->Du->Dc);

	DuWoLSetControlEnable(hWnd, false);

	// メイン
	err = DcTriggerWoL(m->Du->Dc, pcid, pcid2);

	if (err != ERR_NO_ERROR)
	{
		// エラー発生
		MsgBox(hWnd, MB_ICONWARNING, _E(err));
	}
	else
	{
		// OK
		ret = true;
	}

	DuWoLSetControlEnable(hWnd, true);

	if (ret)
	{
		MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("DU_WOL_MSG"), pcid, pcid2);
	}

	FocusEx(hWnd, C_PCID);

	return ret;
}

// WoL ダイアログプロシージャ
UINT DuWoLDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *m = (DU_MAIN *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuWoLDlgInit(hWnd, m);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			DuWoLDlgOnOk(hWnd, m);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// WoL ダイアログ
bool DuWoLDlg(HWND hWnd, DU_MAIN *m)
{
	if (m == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_DU_WOL, DuWoLDlgProc, m);
}

// コントロール更新
void DuOtpDlgUpdate(HWND hWnd)
{
	char pass[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_OTP, pass, sizeof(pass));

	SetEnable(hWnd, IDOK, StrLen(pass) == 0 ? false : true);
}

// OTP ダイアログプロシージャ
UINT DuOtpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_OTP *t = (DU_OTP *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DlgFont(hWnd, S_1, 0, true);

		SetFont(hWnd, E_OTP, GetFont(MsIsWindows7() ? "Consolas" : "Arial", 12, false, false, false, false));

		SetIcon(hWnd, 0, ICO_IPSEC);
		FormatText(hWnd, S_TITLE, t->Hostname);
		Focus(hWnd, E_OTP);
		DuOtpDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		DuOtpDlgUpdate(hWnd);

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_OTP, t->Otp, sizeof(t->Otp));
			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// OTP ダイアログ
bool DuOtpDlg(HWND hWnd, char *otp, UINT otp_size, char *hostname)
{
	DU_OTP t;
	UINT ret;
	// 引数チェック
	if (otp == NULL)
	{
		return false;
	}
	if (hostname == NULL)
	{
		hostname = "";
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Hostname, sizeof(t.Hostname), hostname);

	ret = Dialog(hWnd, D_DU_OTP, DuOtpDlgProc, &t);

	if (ret == 0)
	{
		return false;
	}

	StrCpy(otp, otp_size, t.Otp);

	return true;
}

// 業務完了 Dlg Proc
UINT DuTheEndDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_THINCLIENT);
		if (MsIsVista())
		{
			SetFont(hWnd, IDCANCEL, GetMeiryoFontEx2(11, true));
		}
		else
		{
			DlgFont(hWnd, IDCANCEL, 11, true);
		}

		Top(hWnd);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			if (IsChecked(hWnd, C_NOMORE))
			{
				MsRegWriteInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME, 0);
			}

			Close(hWnd);
			break;
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// 業務完了
void DuTheEndDlg(HWND hWnd)
{
	Dialog(hWnd, D_DU_THEEND, DuTheEndDlgProc, NULL);
}

bool DuDialupDlg(HWND hWnd)
{
	return DialogEx2(hWnd, D_DU_DIALUP, DuDialupDlgProc, NULL, false, false);
}

static HINSTANCE hWinMM = NULL;
static BOOL (WINAPI *_PlaySoundW)(LPCWSTR, HMODULE, DWORD) = NULL;

UINT DuDialupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	wchar_t tmp[MAX_PATH];
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_VB6);
		if (hWinMM == NULL)
		{
			hWinMM = LoadLibraryA("winmm.dll");
		}
		if (_PlaySoundW == NULL)
		{
			if (hWinMM != NULL)
			{
				_PlaySoundW = (UINT (__stdcall *)(LPCWSTR,HMODULE,DWORD))GetProcAddress(hWinMM, "PlaySoundW");
			}
		}
		CombinePathW(tmp, sizeof(tmp), MsGetMyTempDirW(), L"dial.wav");
		if (IsFileExistsW(tmp) == false)
		{
			FileCopyW(L"|dial.wav", tmp);
		}
		if (_PlaySoundW != NULL)
		{
			_PlaySoundW(tmp, NULL, SND_FILENAME | SND_ASYNC | SND_NOWAIT);
		}
		SetFont(hWnd, S_STATIC, GetFont(_SS("DASAI_FONT"), 9, false, false, false, false));
		SetFont(hWnd, IDCANCEL, GetFont(_SS("DASAI_FONT"), 9, false, false, false, false));
		SetTimer(hWnd, 1, 24 * 1000, NULL);
		Top(hWnd);
		Center(hWnd);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SetText(hWnd, S_STATIC, _UU("DU_DIALUP_CONNECTING"));
			SetTimer(hWnd, 2, Rand32() % 1500 + 1000, NULL);
			break;

		case 2:
			KillTimer(hWnd, 2);
			EndDialog(hWnd, 1);
			PlaySoundW(NULL, NULL, SND_ASYNC);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		PlaySoundW(NULL, NULL, SND_ASYNC);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// コントロール更新
void DuShareDlgUpdate(HWND hWnd)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, S_INFO, IsChecked(hWnd, C_SHARE_DISK) || IsChecked(hWnd, C_SHARE_CLIPBOARD));
	SetEnable(hWnd, B_USAGE, IsChecked(hWnd, C_SHARE_DISK) || IsChecked(hWnd, C_SHARE_CLIPBOARD));
}

// 共有ダイアログプロシージャ
UINT DuShareDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *m = (DU_MAIN *)param;
	DC *dc = m->Du->Dc;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SHARE);
		DlgFont(hWnd, C_USE, 0, true);
		DlgFont(hWnd, C_SHARE_CLIPBOARD, 0, true);
		DlgFont(hWnd, C_SHARE_DISK, 0, true);
		DlgFont(hWnd, C_SHARE_PRINTER, 0, true);
		DlgFont(hWnd, C_SHARE_COMPORT, 0, true);
		DlgFont(hWnd, C_SHARE_CAMERA, 0, true);
		DlgFont(hWnd, C_SHARE_AUDIOREC, 0, true);

		if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") == false)
		{
			Check(hWnd, C_SHARE_CLIPBOARD, dc->MstscUseShareClipboard);
			Check(hWnd, C_SHARE_DISK, dc->MstscUseShareDisk);
			Check(hWnd, C_SHARE_PRINTER, dc->MstscUseSharePrinter);
			Check(hWnd, C_SHARE_COMPORT, dc->MstscUseShareComPort);
			Check(hWnd, C_SHARE_CAMERA, dc->MstscUseShareCamera);
			Check(hWnd, C_SHARE_AUDIOREC, dc->MstscUseShareAudioRec);

			SetEnable(hWnd, C_SHARE_CLIPBOARD, DcGetCurrentMstscVersion(dc) == DC_MSTSC_VER_VISTA);
			if (IsEnable(hWnd, C_SHARE_CLIPBOARD) == false)
			{
				Check(hWnd, C_SHARE_CLIPBOARD, true);
			}
		}
		else
		{
			Check(hWnd, C_SHARE_CLIPBOARD, false);
			Check(hWnd, C_SHARE_DISK, false);
			Check(hWnd, C_SHARE_PRINTER, false);
			Check(hWnd, C_SHARE_COMPORT, false);
			Check(hWnd, C_SHARE_CAMERA, false);
			Check(hWnd, C_SHARE_AUDIOREC, false);

			Disable(hWnd, C_SHARE_CLIPBOARD);
			Disable(hWnd, C_SHARE_DISK);
			Disable(hWnd, C_SHARE_PRINTER);
			Disable(hWnd, C_SHARE_COMPORT);
			Disable(hWnd, C_SHARE_CAMERA);
			Disable(hWnd, C_SHARE_AUDIOREC);

			Disable(hWnd, IDOK);
		}

		DuShareDlgUpdate(hWnd);

		if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
		{
			// 説教
			SetText(hWnd, S_S1, _UU("DU_SOUMU_DISABLE_SHARE"));
			DlgFont(hWnd, S_S1, 0, true);
			Hide(hWnd, S_INFO_ICON);
			Hide(hWnd, S_INFO_2);
			Hide(hWnd, S_INFO_3);

			SetTimer(hWnd, 1, 100, NULL);
		}

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case C_SHARE_CLIPBOARD:
		case C_SHARE_DISK:
		case C_SHARE_PRINTER:
		case C_SHARE_COMPORT:
			DuShareDlgUpdate(hWnd);
			break;

		case IDOK:
			dc = m->Du->Dc;
			if (IsEnable(hWnd, C_SHARE_CLIPBOARD))
			{
				dc->MstscUseShareClipboard = IsChecked(hWnd, C_SHARE_CLIPBOARD);
			}

			dc->MstscUseShareDisk = IsChecked(hWnd, C_SHARE_DISK);
			dc->MstscUseSharePrinter = IsChecked(hWnd, C_SHARE_PRINTER);
			dc->MstscUseShareComPort = IsChecked(hWnd, C_SHARE_COMPORT);
			dc->MstscUseShareCamera = IsChecked(hWnd, C_SHARE_CAMERA);
			dc->MstscUseShareAudioRec = IsChecked(hWnd, C_SHARE_AUDIOREC);

			if (dc->MstscUseShareCamera)
			{
				OnceMsgEx2(hWnd, _UU("PRODUCT_NAME_DESKCLIENT"), _UU("DU_MSTSC_CAMERA_WARNING"), true,
					ICO_INFORMATION, NULL, false);
			}

			EndDialog(hWnd, 1);

			break;

		case B_USAGE:
			OnceMsgEx2(hWnd, _UU("PRODUCT_NAME_DESKCLIENT"), _UU("DU_DISK_SHARE_HELP"), false, ICO_INFORMATION, NULL, false);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("DU_SOUMU_DISABLE_SHARE"));

			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// 共有ダイアログ
void DuShareDlg(HWND hWnd, DU_MAIN *m)
{
	// 引数チェック
	if (m == NULL)
	{
		return;
	}

	Dialog(hWnd, D_DU_SHARE, DuShareDlgProc, m);
}

// バージョン情報プロシージャ
UINT DuAboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_ABOUT *t = (DU_ABOUT *)param;
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, t->Icon);
		SetIcon(hWnd, S_ICON, t->Icon);
		SetTextA(hWnd, S_TITLE, t->SoftName);
		FormatText(hWnd, S_VERSION,
			DESK_VERSION / 100, DESK_VERSION % 100,
			DESK_BUILD);
		SetTextA(hWnd, S_BUILDINFO, t->BuildInfo);
		DlgFont(hWnd, S_TITLE, 13, true);
		DlgFont(hWnd, S_VERSION, 0, true);
		DlgFont(hWnd, S_BETA, 0, true);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			EndDialog(hWnd, 1);
			break;

		case B_WEB:
			MsExecute(_SS("DESKTOPVPN_URL"), NULL);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// バージョン情報ダイアログ
void DuAboutDlg(HWND hWnd, UINT icon, char *softname, char *buildinfo)
{
	DU_ABOUT t;
	// 引数チェック
	if (softname == NULL || buildinfo == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Icon = icon;
	t.SoftName = softname;
	t.BuildInfo = buildinfo;

	Dialog(hWnd, D_DU_ABOUT, DuAboutDlgProc, &t);
}

// URDP メッセージプロシージャ
UINT DuUrdpMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_URDPMSG *t = (DU_URDPMSG *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		t->hWnd = hWnd;
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		t->DontShow = IsChecked(hWnd, B_NOAGAIN);
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// URDP メッセージスレッド
void DuUrdpMsgThread(THREAD *thread, void *param)
{
	DU_URDPMSG *t;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	t = (DU_URDPMSG *)param;

	Dialog(NULL, D_DU_URDPMSG, DuUrdpMsgProc, t);
}

// URDP メッセージの停止
void DuUrdpMsgStop(DU_MAIN *m, DU_URDPMSG *t)
{
	DC *dc;
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	if (m == NULL || t == NULL)
	{
		return;
	}


	dc = m->Du->Dc;

	PostMessage(t->hWnd, WM_CLOSE, 0, 0);

	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);

	dc->DontShowFullScreenMessage = t->DontShow;
	DcSaveConfig(dc);

	Free(t);
}

// URDP メッセージの開始
DU_URDPMSG *DuUrdpMsgStart(DU_MAIN *m)
{
	DC *dc;
	DU_URDPMSG *t;
	// 引数チェック
	if (m == NULL)
	{
		return NULL;
	}

	dc = m->Du->Dc;

	if (dc->DontShowFullScreenMessage)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(DU_URDPMSG));
	t->Thread = NewThread(DuUrdpMsgThread, t);

	while (t->hWnd == NULL)
	{
		SleepThread(100);
	}

	return t;
}

// ダイアログ初期化
void DuConnectDlgInit(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	DisableClose(hWnd);

	SetIcon(hWnd, 0, ICO_LICENSE);

	t->hWndConnect = hWnd;

	FormatText(hWnd, S_INFO, t->Pcid);
	DlgFont(hWnd, S_INFO, 0, true);

	SetTimer(hWnd, 1, 100, NULL);
}

// 接続処理の開始
void DuConnectDlgOnTimer(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	KillTimer(hWnd, 1);

	// システムがスリープしないようにする
	MsStartEasyNoSleep();

	DuConnectMain(hWnd, t, t->Pcid);

	// システムがスリープしても良いように戻す
	MsStopEasyNoSleep();

	EndDialog(hWnd, 1);

	t->hWndConnect = NULL;
}

// 接続ダイアログプロシージャ
UINT DuConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *t = (DU_MAIN *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuConnectDlgInit(hWnd, t);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			DuConnectDlgOnTimer(hWnd, t);
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// 接続ダイアログを開く
void DuConnectDlg(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (t == NULL)
	{
		return;
	}

	Dialog(hWnd, D_DU_CONNECT, DuConnectDlgProc, t);
}

// コントロール更新
void DuPasswordDlgUpdate(HWND hWnd)
{
	char pass[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_PASSWORD, pass, sizeof(pass));

	SetEnable(hWnd, IDOK, StrLen(pass) == 0 ? false : true);
}

// パスワードダイアログプロシージャ
UINT DuPasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_PASSWORD *t = (DU_PASSWORD *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_KEY);
		FormatText(hWnd, S_TITLE, t->Hostname);
		Focus(hWnd, E_PASSWORD);
		DuPasswordDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		DuPasswordDlgUpdate(hWnd);

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_PASSWORD, t->Password, sizeof(t->Password));
			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// パスワードダイアログ
bool DuPasswordDlg(HWND hWnd, char *password, UINT password_size, char *hostname)
{
	DU_PASSWORD t;
	UINT ret;
	// 引数チェック
	if (password == NULL)
	{
		return false;
	}
	if (hostname == NULL)
	{
		hostname = "";
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Hostname, sizeof(t.Hostname), hostname);

	ret = Dialog(hWnd, D_DU_PASSWORD, DuPasswordDlgProc, &t);

	if (ret == 0)
	{
		return false;
	}

	StrCpy(password, password_size, t.Password);

	return true;
}

// イベントコールバック
bool DuEventCallback(DC_SESSION *s, UINT event_type, void *event_param)
{
	char *url;
	DU_MAIN *t;
	HINSTANCE ret;
	// 引数チェック
	if (s == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)s->Param;

	switch (event_type)
	{
	case DC_EVENT_URL_RECVED:
		// URL を受信
		url = (char *)event_param;
		ret = ShellExecuteA(t->hWnd, "open", url, NULL, NULL, SW_SHOW);
		if ((UINT64)ret <= 32)
		{
			// 失敗したのでメッセージを表示する
			MsgBoxEx(t->hWndConnect, MB_ICONINFORMATION, _UU("DU_URL_ERROR"),
				url);
		}
		break;

	case DC_EVENT_MSG_RECVED:
		// メッセージを受信した。表示する
		{
			wchar_t *msg = (wchar_t *)event_param;

			OnceMsgEx(t->hWndConnect, _UU("DU_SERVER_MSG"), msg, false, ICO_VB6, NULL);
		}
		break;
	}

	return true;
}

// パスワードコールバック
bool DuPasswordCallback(DC_SESSION *s, char *password, UINT password_max_size)
{
	DU_MAIN *t;
	HWND hWnd;
	// 引数チェック
	if (s == NULL || password == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)s->Param;

	hWnd = t->hWnd;

	if (DuPasswordDlg(hWnd, password, password_max_size, s->Pcid) == false)
	{
		return false;
	}

	return true;
}

// 検疫 コールバック
bool DuInspectionCallback(DC *dc, DC_INSPECT *ins, DC_SESSION *dcs)
{
	DU_MAIN *t;
	HWND hWnd;
	// 引数チェック
	if (dc == NULL || dcs == NULL || ins == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)dcs->Param;

	hWnd = t->hWnd;

	if (DuInspectionDlg(hWnd, ins) == false)
	{
		return false;
	}

	return true;
}

// 検疫ダイアログ
bool DuInspectionDlg(HWND hWnd, DC_INSPECT *ins)
{
	if (ins == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_DU_INSPECT, DuInspectionDlgProc, ins);
}

// 検疫ダイアログプロシージャ
UINT DuInspectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DC_INSPECT *ins = (DC_INSPECT *)param;
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SHIELD);
		DisableClose(hWnd);
		SetTimer(hWnd, 1, 300, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			DoEvents(hWnd);
			ins->AntiVirusOk = MsCheckAntiVirus();

			DoEvents(hWnd);
			ins->WindowsUpdateOk = MsCheckWindowsUpdate();

			if (DcGetDebugFlag())
			{
				ins->AntiVirusOk = true;
				ins->WindowsUpdateOk = true;
			}

			DoEvents(hWnd);
			GetMacAddressListLocalComputer(ins->MacAddressList, sizeof(ins->MacAddressList), false);

			DoEvents(hWnd);

			EndDialog(hWnd, 1);

			break;
		}

		break;

	case WM_CLOSE:
		break;
	}

	return 0;
}

// OTP コールバック
bool DuOtpCallback(DC *dc, char *otp, UINT otp_max_size, DC_SESSION *dcs)
{
	DU_MAIN *t;
	HWND hWnd;
	// 引数チェック
	if (dc == NULL || dcs == NULL || otp == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)dcs->Param;

	hWnd = t->hWnd;

	if (DuOtpDlg(hWnd, otp, otp_max_size, dcs->Pcid) == false)
	{
		return false;
	}

	return true;
}

// 認証ダイアログ初期化
void DuAuthDlgInit(HWND hWnd, DU_AUTH *a)
{
	DC_ADVAUTH *aa;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	SetTextA(hWnd, S_CERT_AND_KEY, "");

	FormatText(hWnd, S_TITLE, a->Pcid);

	aa = DcGetAdvAuth(a->Dc, a->Pcid);
	if (aa != NULL)
	{
		SetTextA(hWnd, E_USERNAME, aa->Username);

		if (aa->AuthType == DESK_AUTH_USERPASSWORD)
		{
			Check(hWnd, C_PASSWORD, true);
			Check(hWnd, C_CERT, false);
			Check(hWnd, C_SMARTCARD, false);

			DuAuthDlgUpdate(hWnd, a);

			if (IsEmpty(hWnd, E_USERNAME) == false)
			{
				FocusEx(hWnd, E_PASSWORD);
			}
			else
			{
				FocusEx(hWnd, E_USERNAME);
			}
		}
		else if (aa->AuthType == DESK_AUTH_CERT)
		{
			Check(hWnd, C_CERT, true);
			Check(hWnd, C_PASSWORD, false);
			Check(hWnd, C_SMARTCARD, false);

			DuAuthDlgUpdate(hWnd, a);

			DuAuthDlgSetCertPath(hWnd, aa->CertPath);

			if (IsEmpty(hWnd, E_USERNAME) == false)
			{
				if (IsEmpty(hWnd, E_CERTPATH))
				{
					Focus(hWnd, B_BROWSE);
				}
				else
				{
					Focus(hWnd, IDOK);
				}
			}
			else
			{
				FocusEx(hWnd, E_USERNAME);
			}
		}
		else if (aa->AuthType == DESK_AUTH_SMARTCARD)
		{
			wchar_t tmp[MAX_PATH];
			SECURE_DEVICE *dev = NULL;

			Check(hWnd, C_SMARTCARD, true);
			Check(hWnd, C_PASSWORD, false);
			Check(hWnd, C_CERT, false);

			dev = GetSecureDevice(aa->SecureDeviceId);

			if (dev != NULL)
			{
				UniFormat(tmp, sizeof(tmp), _UU("DU_AUTH_SMARTCARD_STR1"), dev->DeviceName);
				SetText(hWnd, S_SMARTCARD_DEVICE, tmp);
				SetText(hWnd, B_SELECT_SMARTCARD, _UU("DU_AUTH_SMARTCARD_CHANGE"));
				DlgFont(hWnd, S_SMARTCARD_DEVICE, 0, true);
			}

			if (IsEmptyStr(aa->SecureCertName) == false && IsEmptyStr(aa->SecureKeyName) == false)
			{
				SetText(hWnd, S_CERT_STR, _UU("DU_AUTH_SMARTCARD_CERT_STR1"));
				DlgFont(hWnd, S_CERT_STR, 0, true);
				UniFormat(tmp, sizeof(tmp), _UU("DU_AUTH_SMARTCARD_CERT_AND_KEY"), aa->SecureCertName, aa->SecureKeyName);
				SetText(hWnd, S_CERT_AND_KEY, tmp);
			}

			DlgFont(hWnd, S_CERT_AND_KEY, 0, true);

			//DuAuthDlgUpdate(hWnd, a);

			if (IsEmpty(hWnd, E_USERNAME) == false)
			{
				if (dev == NULL)
				{
					Focus(hWnd, B_SELECT_SMARTCARD);
				}
				else
				{
					if (IsEmptyStr(aa->SecureCertName) == false && IsEmptyStr(aa->SecureKeyName) == false)
					{
						Focus(hWnd, IDOK);
					}
					else
					{
						Focus(hWnd, B_SELECT_SCARD_CERT);
					}
				}
			}
			else
			{
				FocusEx(hWnd, E_USERNAME);
			}

			a->SecureDeviceId = aa->SecureDeviceId;
			StrCpy(a->SecureCertName, sizeof(a->SecureCertName), aa->SecureCertName);
			StrCpy(a->SecureKeyName, sizeof(a->SecureKeyName), aa->SecureKeyName);
		}
	}
	else
	{
		Check(hWnd, C_PASSWORD, true);
		Check(hWnd, C_CERT, false);
		Check(hWnd, C_SMARTCARD, false);

		FocusEx(hWnd, E_USERNAME);
	}

	// コントロール更新
	DuAuthDlgUpdate(hWnd, a);
}

// 認証ダイアログ更新
void DuAuthDlgUpdate(HWND hWnd, DU_AUTH *a)
{
	bool b = true, b1 = true, b2 = true, b3 = true;
	bool b4 = false;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, C_CERT))
	{
		b1 = false;
		b3 = false;

		if (IsEmpty(hWnd, E_CERTPATH))
		{
			b = false;
		}
	}
	else if (IsChecked(hWnd, C_SMARTCARD))
	{
		b1 = false;
		b2 = false;

		if (a->SecureDeviceId == 0 || IsEmptyStr(a->SecureCertName) || IsEmptyStr(a->SecureKeyName))
		{
			b = false;
		}

		if (a->SecureDeviceId != 0)
		{
			b4 = true;
		}
	}
	else
	{
		b2 = false;
		b3 = false;
	}

	if (IsEmpty(hWnd, E_USERNAME))
	{
		b = false;
	}

	SetEnable(hWnd, S_S1, b1);
	SetEnable(hWnd, S_S2, b1);
	SetEnable(hWnd, E_PASSWORD, b1);

	SetEnable(hWnd, S_S4, b2);
	SetEnable(hWnd, E_CERTPATH, b2);
	SetEnable(hWnd, B_BROWSE, b2);

	SetEnable(hWnd, S_SMARTCARD_DEVICE, b3);
	SetEnable(hWnd, B_SELECT_SMARTCARD, b3);
	SetEnable(hWnd, S_CERT_STR, b3 && b4);
	SetEnable(hWnd, B_SELECT_SCARD_CERT, b3 && b4);
	SetEnable(hWnd, S_CERT_AND_KEY, b3 && b4);

	SetEnable(hWnd, IDOK, b);
}

// 証明書パスを指定する
void DuAuthDlgSetCertPath(HWND hWnd, wchar_t *path)
{
	// 引数チェック
	if (hWnd == NULL || path == NULL)
	{
		return;
	}

	SetText(hWnd, E_CERTPATH, path);

	FocusEx(hWnd, IDOK);
}

// OK ボタンをクリックした
void DuAuthDlgOnOk(HWND hWnd, DU_AUTH *a)
{
	wchar_t tmp[MAX_PATH];
	DC_AUTH aa;
	DC_ADVAUTH ad;
	// 引数チェック
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	Zero(&aa, sizeof(aa));

	aa.UseAdvancedSecurity = true;

	GetTxtA(hWnd, E_USERNAME, aa.RetUsername, sizeof(aa.RetUsername));

	if (IsChecked(hWnd, C_CERT))
	{
		X *x;
		K *k;
		BUF *buf_x, *buf_k;

		// 証明書認証
		aa.AuthType = DESK_AUTH_CERT;

		GetTxt(hWnd, E_CERTPATH, tmp, sizeof(tmp));

		// 証明書と秘密鍵を読み込む
		if (CmLoadXAndKEx(hWnd, &x, &k, tmp, NULL, true) == false)
		{
			FocusEx(hWnd, E_CERTPATH);
			return;
		}

		buf_x = XToBuf(x, false);
		buf_k = KToBuf(k, false, NULL);
		FreeX(x);
		FreeK(k);

		aa.RetCertSize = MIN(buf_x->Size, sizeof(aa.RetCertData));
		Copy(aa.RetCertData, buf_x->Buf, aa.RetCertSize);

		aa.RetKeySize = MIN(buf_k->Size, sizeof(aa.RetKeyData));
		Copy(aa.RetKeyData, buf_k->Buf, aa.RetKeySize);

		FreeBuf(buf_x);
		FreeBuf(buf_k);
	}
	else if (IsChecked(hWnd, C_SMARTCARD))
	{
		// スマートカード認証
		aa.AuthType = DESK_AUTH_SMARTCARD;
	}
	else
	{
		// パスワード認証
		aa.AuthType = DESK_AUTH_USERPASSWORD;
		GetTxtA(hWnd, E_PASSWORD, aa.RetPassword, sizeof(aa.RetPassword));
	}

	Zero(&ad, sizeof(ad));
	StrCpy(ad.Pcid, sizeof(ad.Pcid), a->Pcid);
	ad.AuthType = aa.AuthType;

	if (IsChecked(hWnd, C_CERT))
	{
		UniStrCpy(ad.CertPath, sizeof(ad.CertPath), tmp);
	}

	if (IsChecked(hWnd, C_SMARTCARD))
	{
		bool ok = false;
		SECURE_SIGN sign;

		ad.SecureDeviceId = a->SecureDeviceId;
		StrCpy(ad.SecureCertName, sizeof(ad.SecureCertName), a->SecureCertName);
		StrCpy(ad.SecureKeyName, sizeof(ad.SecureKeyName), a->SecureKeyName);

		Zero(&sign, sizeof(sign));

		StrCpy(sign.SecurePublicCertName, sizeof(sign.SecurePublicCertName), ad.SecureCertName);
		StrCpy(sign.SecurePrivateKeyName, sizeof(sign.SecurePrivateKeyName), ad.SecureKeyName);
		Copy(sign.Random, a->Auth.InRand, sizeof(sign.Random));
		sign.UseSecureDeviceId = a->SecureDeviceId;

		ok = Win32CiSecureSign(&sign);

		if (ok)
		{
			BUF *x_buf = XToBuf(sign.ClientCert, false);

			if (x_buf != NULL && x_buf->Size <= DC_MAX_SIZE_CERT && sign.ClientCert->is_compatible_bit)
			{
				Copy(aa.RetCertData, x_buf->Buf, x_buf->Size);
				aa.RetCertSize = x_buf->Size;

				Copy(aa.RetSignedData, sign.Signature, sign.ClientCert->bits / 8);
				aa.RetSignedDataSize = sign.ClientCert->bits / 8;
			}

			FreeBuf(x_buf);
		}

		FreeRpcSecureSign(&sign);

		if (ok == false)
		{
			// 署名失敗
			return;
		}
	}
	
	StrCpy(ad.Username, sizeof(ad.Username), aa.RetUsername);

	DcSetAdvAuth(a->Dc, &ad);

	Copy(&a->Auth, &aa, sizeof(DC_AUTH));

	EndDialog(hWnd, true);
}

// 認証ダイアログプロシージャ
UINT DuAuthDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_AUTH *a = (DU_AUTH *)param;
	wchar_t *s;
	// 引数チェック
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		DuAuthDlgInit(hWnd, a);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_USERNAME:
		case E_PASSWORD:
		case E_CERTPATH:
			DuAuthDlgUpdate(hWnd, a);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			DuAuthDlgOnOk(hWnd, a);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_BROWSE:
			s = OpenDlg(hWnd, _UU("DLG_PKCS12_ONLY_FILTER"), _UU("DLG_OPEN_CERT_P12"));
			if (s != NULL)
			{
				DuAuthDlgSetCertPath(hWnd, s);

				Free(s);
				DuAuthDlgUpdate(hWnd, a);
			}
			break;

		case C_PASSWORD:
			DuAuthDlgUpdate(hWnd, a);

			if (IsChecked(hWnd, C_PASSWORD))
			{
				if (IsEmpty(hWnd, E_USERNAME) == false)
				{
					FocusEx(hWnd, E_PASSWORD);
				}
				else
				{
					FocusEx(hWnd, E_USERNAME);
				}
			}
			break;

		case C_CERT:
			DuAuthDlgUpdate(hWnd, a);

			if (IsChecked(hWnd, C_CERT))
			{
				if (IsEmpty(hWnd, E_USERNAME) == false)
				{
					FocusEx(hWnd, B_BROWSE);
				}
				else
				{
					FocusEx(hWnd, E_USERNAME);
				}
			}
			break;

		case C_SMARTCARD:
			DuAuthDlgUpdate(hWnd, a);

			if (IsChecked(hWnd, C_SMARTCARD))
			{
				if (IsEmpty(hWnd, E_USERNAME) == false)
				{
					if (a->SecureDeviceId == 0)
					{
						Focus(hWnd, B_SELECT_SMARTCARD);
					}
					else
					{
						Focus(hWnd, B_SELECT_SCARD_CERT);
					}
				}
				else
				{
					FocusEx(hWnd, E_USERNAME);
				}
			}
			break;

		case B_SELECT_SMARTCARD: // スマートカード選択
			{
				wchar_t tmp[MAX_PATH];
				SECURE_DEVICE *dev = NULL;
				UINT id = CmSelectSecure(hWnd, a->SecureDeviceId);
				if (id != 0)
				{
					dev = GetSecureDevice(id);

					if (dev != NULL)
					{
						UniFormat(tmp, sizeof(tmp), _UU("DU_AUTH_SMARTCARD_STR1"), dev->DeviceName);
						SetText(hWnd, S_SMARTCARD_DEVICE, tmp);
						SetText(hWnd, B_SELECT_SMARTCARD, _UU("DU_AUTH_SMARTCARD_CHANGE"));
						DlgFont(hWnd, S_SMARTCARD_DEVICE, 0, true);

						a->SecureDeviceId = id;
					}
				}

				DuAuthDlgUpdate(hWnd, a);
			}
			break;

		case B_SELECT_SCARD_CERT:	// スマートカード内の鍵選択
			{
				wchar_t tmp[MAX_PATH];
				char cert[MAX_SECURE_DEVICE_FILE_LEN + 1], priv[MAX_SECURE_DEVICE_FILE_LEN + 1];

				// Select a certificate in the smart card
				if (SmSelectKeyPair(hWnd, cert, sizeof(cert), priv, sizeof(priv)))
				{
					StrCpy(a->SecureCertName, sizeof(a->SecureCertName), cert);
					StrCpy(a->SecureKeyName, sizeof(a->SecureKeyName), priv);

					SetText(hWnd, S_CERT_STR, _UU("DU_AUTH_SMARTCARD_CERT_STR1"));
					DlgFont(hWnd, S_CERT_STR, 0, true);
					UniFormat(tmp, sizeof(tmp), _UU("DU_AUTH_SMARTCARD_CERT_AND_KEY"), a->SecureCertName, a->SecureKeyName);
					SetText(hWnd, S_CERT_AND_KEY, tmp);

					DuAuthDlgUpdate(hWnd, a);
				}
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// 認証ダイアログ
bool DuAuthDlg(HWND hWnd, DU_MAIN *t, char *pcid, DC_AUTH *auth)
{
	UINT ret;
	DU_AUTH a;
	// 引数チェック
	if (t == NULL || pcid == NULL || auth == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));

	a.Du = t->Du;
	a.Dc = a.Du->Dc;

	StrCpy(a.Pcid, sizeof(a.Pcid), pcid);

	Copy(a.Auth.InRand, auth->InRand, SHA1_SIZE);

	ret = Dialog(hWnd, D_DU_AUTH, DuAuthDlgProc, &a);

	if (ret == 0)
	{
		return false;
	}

	Copy(auth, &a.Auth, sizeof(DC_AUTH));

	return true;
}

// 新しい認証方法のコールバック
bool DuAdvAuthCallback(DC_SESSION *s, DC_AUTH *auth)
{
	DU_MAIN *t;
	HWND hWnd;
	// 引数チェック
	if (s == NULL || auth == NULL)
	{
		return false;
	}

	t = (DU_MAIN *)s->Param;

	hWnd = t->hWnd;

	if (DuAuthDlg(hWnd, t, s->Pcid, auth) == false)
	{
		return false;
	}

	return true;
}

// 接続処理メイン
void DuConnectMain(HWND hWnd, DU_MAIN *t, char *pcid)
{
	wchar_t mstsc[MAX_PATH];
	bool need_download = false;
	DC_SESSION *s;
	DC *dc;
	UINT ret;
	wchar_t lifetime_msg[MAX_PATH] = {0};
	DESKTOP_WATERMARK *water = NULL;
	bool restore_window = false;
	// 引数チェック
	if (hWnd == NULL || t == NULL || pcid == NULL)
	{
		return;
	}

	Zero(lifetime_msg, sizeof(lifetime_msg));

	dc = t->Du->Dc;

	if (DcGetMstscPath(dc, mstsc, sizeof(mstsc), &need_download) == false)
	{
		// mstsc の設定が不十分
		if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO, _UU("DU_NO_MSTSC_CONFIG")) == IDYES)
		{
			DuOptionDlg(hWnd, t);
		}
		return;
	}

	if (need_download)
	{
		// ダウンロードを実施する
		if (DuDownloadMstsc(hWnd, t) == false)
		{
			return;
		}
	}

	// セッション接続
	ret = NewDcSession(dc, pcid, DuPasswordCallback, DuOtpCallback, DuAdvAuthCallback, DuEventCallback, DuInspectionCallback, t, &s);
	if (ret != ERR_NO_ERROR)
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));
		return;
	}

	ret = DcSessionConnect(s);
	if (ret != ERR_NO_ERROR)
	{
		if (ret != ERR_RECV_URL && ret != ERR_RECV_MSG)
		{
			MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));
		}
	}
	else
	{
		bool dialup_ok = true;

		wchar_t exe[MAX_PATH];
		char arg[MAX_PATH];
		UINT ret = ERR_NO_ERROR;
		void *process = NULL;
		DU_URDPMSG *msg = NULL;
		ONCEMSG_DLG *once = NULL;
		UINT process_id = 0;
		bool rdp_file_write_failed = false;
		UINT urdp_version = 0;
		bool gov_fw_ok = true;
		bool need_to_watch_gov_fw = false;

		if (MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_ENABLE_RELAX_KEY_NAME) && Vars_ActivePatch_GetBool("ThinTelework_DisableOmakeFunctions") == false)
		{
			Hide(t->hWnd, 0);
			Hide(t->hWndConnect, 0);
			dialup_ok = DuDialupDlg(NULL);
			Show(t->hWndConnect, 0);
			Show(t->hWnd, 0);
		}

		if ((Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") == false && s->IsLimitedMode && (dc->DisableLimitedFw == false || s->IsEnspectionEnabled)) || (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") && dc->DisableLimitedFw == false) || (Vars_ActivePatch_GetInt("ThinFwMode") == 1 && dc->DisableLimitedFw == false) || (Vars_ActivePatch_GetInt("ThinFwMode") == 2) || s->IsLimitedFirewallMandated)
		{
			bool mandate = s->IsEnspectionEnabled;

			if (Vars_ActivePatch_GetInt("ThinFwMode") == 2)
			{
				// Vars で強制がされている
				mandate = true;
			}

			if (s->IsLimitedFirewallMandated)
			{
				// ポリシーで完全閉域化 FW を強制有効する設定になっている
				mandate = true;
			}

			// 接続先サーバーが「行政システム適応モード」の場合はファイアウォールを
			// 勧める画面を表示する
			if (MsIsVista())
			{
				if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity") && Vars_ActivePatch_GetInt("ThinFwMode") != 2 && s->IsLimitedFirewallMandated == false)
				{
					// 2020/10/02 ThinTelework_EnforceStrongSecurity が ON の場合は
					// mandate をしないようにする
					mandate = false;
				}

				gov_fw_ok = DuGovFw1Main(mandate);

				need_to_watch_gov_fw = mandate;
			}
			else
			{
				// Windows XP またはそれ以前ではファイアウォール機能が利用できない
				gov_fw_ok = false;
			}

			if (mandate == false)
			{
				// 検疫有効でない場合等、mandate == false の場合は、いかなる場合でも gov fw は成功したとみなす
				gov_fw_ok = true;
			}
		}

		if (dialup_ok == false || gov_fw_ok == false)
		{
			// キャンセルされた
		}
		else
		{
			if (s->ServiceType == DESK_SERVICE_RDP)
			{
				// リモートデスクトップクライアントの実行
				// RDP
				UniStrCpy(exe, sizeof(exe), mstsc);

				ret = DcGetMstscArguments(s, exe, arg, sizeof(arg));

				if (ret == ERR_NO_ERROR)
				{
					process = DcRunMstsc(dc, exe, arg, s->IsShareDisabled, &process_id, &rdp_file_write_failed);
				}
			}
			else
			{
				if (s->DsCaps & DS_CAPS_SUPPORT_URDP2)
				{
					urdp_version = 2;
				}

				// URDP
				ret = DcGetUrdpClientArguments(s, arg, sizeof(arg), s->IsShareDisabled, urdp_version);

				if (ret == ERR_NO_ERROR)
				{
					process = DcRunUrdpClient(arg, &process_id, urdp_version);

					if (process != NULL)
					{
						wchar_t *once_msg = NULL;
						wchar_t tmp[MAX_SIZE];
						UINT tmp2_size = 3600;
						wchar_t *tmp2 = ZeroMalloc(tmp2_size);

						if (urdp_version <= 1)
						{
							// URDP1 の使い方のメッセージ
							msg = DuUrdpMsgStart(t);
						}

						// URDP の場合必ず表示する Once Msg
						if (s->DsCaps & DS_CAPS_RUDP_VERY_LIMITED)
						{
							once_msg = _UU("DU_ONCEMSG_1");
						}
						else
						{
							if (s->DsCaps & DS_CAPS_WIN_RDP_ENABLED)
							{
								once_msg = _UU("DU_ONCEMSG_3");
							}
							else
							{
								once_msg = _UU("DU_ONCEMSG_2");
							}
						}

						UniFormat(tmp, sizeof(tmp), _UU("DU_ONCEMSG_TITLE"), s->Pcid);

						UniFormat(tmp2, tmp2_size, once_msg, s->Pcid);

						once = StartAsyncOnceMsg(tmp, tmp2, true, ICO_INFORMATION, true);

						Free(tmp2);
					}
				}
			}

			if (ret == ERR_NO_ERROR)
			{
				if (process == NULL)
				{
					// プロセス起動失敗
					ret = ERR_DESK_PROCESS_EXEC_FAILED;

					if (s->IsShareDisabled && rdp_file_write_failed)
					{
						// .rdp ファイルに書き込めない
						ret = ERR_DESK_RDP_FILE_WRITE_ERROR;
					}
				}
				else
				{
					UINT timeout = INFINITE;
					bool timeouted = false;
					s->ProcessIdOfClient = process_id;

					// プロセス起動成功
					Hide(hWnd, 0);
					Hide(t->hWnd, 0);
					restore_window = true;

					if (UniIsEmptyStr(s->WatermarkStr1) == false)
					{
						// 透かしを描画
						DESKTOP_WATERMARK_SETTING set;
						char *font_name = _SS("DU_FELONY_FONT_XP");

						if (MsIsWindows7())
						{
							font_name = _SS("DU_FELONY_FONT_7");
						}

						Zero(&set, sizeof(set));

						// Print Screen キーを無効化
						set.DisablePrintScreen = true;
						set.EmptyBitmapClipboard = true;

						StrCpy(set.WindowTitle, sizeof(set.WindowTitle), "Thin Telework Watermark");

						UniStrCpy(set.Text1, 0, s->WatermarkStr1);
						UniStrCpy(set.Text2, 0, s->WatermarkStr2);

						set.RandSeed = Rand32();

						set.FontSize1 = 14;

						StrCpy(set.FontName1, 0, font_name);
						StrCpy(set.FontName2, 0, font_name);
						set.FontSize2 = 9;

						set.TextColor1 = RGB(2, 200, 81);
						set.TextColor2 = RGB(2, 200, 81);
						set.Alpha = 20;//192;//128;//9;

						if (DcGetDebugFlag())
						{
							// デバッグのときは少し濃くする
							set.Alpha = 70;
						}

						//set.Alpha = 70;

						set.Margin = 15;

						water = StartDesktopWatermark(&set);
					}

					if (s->LifeTime != 0 && s->LifeTime < INFINITE)
					{
						// 有効期限あり
						timeout = (UINT)s->LifeTime;
					}

					UINT exit_code = 0;

					// プロセスが終了 or タイムアウト するまで待つ
					timeouted = !DcWaitForProcessExit(process, timeout, need_to_watch_gov_fw, s->IdleTimeout * 1000ULL, &exit_code);

					if (water != NULL)
					{
						StopDesktopWatermark(water);
					}

					if (msg != NULL)
					{
						DuUrdpMsgStop(t, msg);
					}

					if (once != NULL)
					{
						StopAsyncOnceMsg(once);
					}

					// 有効期限満了メッセージの準備
					if (timeout != INFINITE && timeouted)
					{
						if (UniIsEmptyStr(s->LifeTimeMsg) == false)
						{
							UniStrCpy(lifetime_msg, sizeof(lifetime_msg), s->LifeTimeMsg);
						}
					}

					if (UniIsEmptyStr(lifetime_msg))
					{
						if (Vars_ActivePatch_GetBool("ThinTelework_DisableOmakeFunctions") == false)
						{
							// お疲れ様でした
							if (MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME))
							{
								DuTheEndDlg(NULL);
							}
						}
					}
				}
			}

			if (ret != ERR_NO_ERROR)
			{
				if (ret != ERR_RECV_URL && ret != ERR_RECV_MSG)
				{
					MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));
				}
			}
		}
	}

	if (restore_window)
	{
		Show(t->hWnd, 0);

		DoEvents(t->hWnd);
	}

	ReleaseDcSession(s);

	if (UniIsEmptyStr(lifetime_msg) == false)
	{
		// 有効期限満了メッセージの表示
		OnceMsgEx2(NULL, _UU("DU_LIFETIME_TITLE"), lifetime_msg, false, ICO_THINCLIENT, NULL, true);
	}
}

// 初期化
void DuDownloadDlgInit(HWND hWnd, DU_DOWNLOAD *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	t->hWnd = hWnd;

	SetRange(hWnd, P_PROGRESS, 0, 100);
	DuDownloadDlgPrintStatus(hWnd, 0, 0);

	SetTimer(hWnd, 1, 100, NULL);
}

// キャンセル
void DuDownloadDlgOnCancel(HWND hWnd, DU_DOWNLOAD *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	t->Halt = true;
}

// ダウンロードメイン処理
void DuDownloadDlgOnTimer(HWND hWnd, DU_DOWNLOAD *t)
{
	UINT ret;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	KillTimer(hWnd, 1);

	// ダウンロード開始
	ret = DcDownloadMstsc(t->Dc, DuDownloadCallback, t);

	if (ret == ERR_NO_ERROR)
	{
		// ダウンロードと展開が完了した
		EndDialog(hWnd, 1);
	}
	else
	{
		// エラー発生
		MsgBox(hWnd, MB_ICONEXCLAMATION, _E(ret));

		EndDialog(hWnd, 0);
	}
}

// ダウンロードコールバック
bool DuDownloadCallback(void *param, UINT total_size, UINT current_size, BUF *recv_buf)
{
	DU_DOWNLOAD *t = (DU_DOWNLOAD *)param;
	HWND hWnd;
	UINT64 now;
	// 引数チェック
	if (t == NULL)
	{
		return false;
	}

	now = Tick64();

	hWnd = t->hWnd;

	if (t->LastTick == 0 || (total_size == current_size) ||
		now > (t->LastTick + 125))
	{
		if (current_size != 0)
		{
			t->LastTick = now;
		}
		DuDownloadDlgPrintStatus(hWnd, current_size, total_size);
	}

	DoEvents(hWnd);

	return t->Halt ? false : true;
}

// ダウンロード状況の表示
void DuDownloadDlgPrintStatus(HWND hWnd, UINT current, UINT total)
{
	wchar_t tmp[MAX_PATH];
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	if (total == 0)
	{
		UniStrCpy(tmp, sizeof(tmp), _UU("DU_DOWNLOAD_INIT"));
		SetPos(hWnd, P_PROGRESS, 0);
		Show(hWnd, P_PROGRESS);
	}
	else
	{
		if (current != total)
		{
			UINT percent = (UINT)((UINT64)current * 100ULL / (UINT64)total);
			char s1[MAX_PATH];
			char s2[MAX_PATH];

			ToStrByte(s1, sizeof(s1), (UINT64)total);
			ToStrByte(s2, sizeof(s2), (UINT64)current);

			UniFormat(tmp, sizeof(tmp), _UU("DU_DOWNLOAD_STATUS"), percent,
				s1, s2);

			SetPos(hWnd, P_PROGRESS, percent);
			Show(hWnd, P_PROGRESS);
		}
		else
		{
			Hide(hWnd, P_PROGRESS);
			UniStrCpy(tmp, sizeof(tmp), _UU("DU_DOWNLOAD_FINISH"));
		}
	}

	SetText(hWnd, S_STATUS, tmp);
}

// ダウンロードダイアログプロシージャ
UINT DuDownloadDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_DOWNLOAD *t = (DU_DOWNLOAD *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuDownloadDlgInit(hWnd, t);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			DuDownloadDlgOnTimer(hWnd, t);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		DuDownloadDlgOnCancel(hWnd, t);
		return 1;
	}

	return 0;
}

// mstsc のダウンロード
bool DuDownloadMstsc(HWND hWnd, DU_MAIN *t)
{
	DC *dc;
	DU_DOWNLOAD d;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return false;
	}

	dc = t->Du->Dc;

	Zero(&d, sizeof(d));
	d.Main = t;
	d.Du = t->Du;
	d.Dc = dc;

	if (Dialog(hWnd, D_DU_DOWNLOAD, DuDownloadDlgProc, &d) == false)
	{
		return false;
	}

	return true;
}

// 初期化
void DuOptionDlgInit(HWND hWnd, DU_OPTION *t)
{
	DC *dc;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	dc = t->Du->Dc;

	DcGetInternetSetting(dc, &t->InternetSetting);

	DlgFont(hWnd, S_PROXY_CONFIG, 0, true);

	SetEnable(hWnd, C_SYSTEM32, DcIsMstscInstalledOnSystem32());

	Check(hWnd, C_SYSTEM32, dc->MstscLocation == DC_MSTSC_SYSTEM32);
	Check(hWnd, C_DOWNLOAD, dc->MstscLocation == DC_MSTSC_DOWNLOAD);
	Check(hWnd, C_USERPATH, dc->MstscLocation == DC_MSTSC_USERPATH);
	SetText(hWnd, E_PATH, dc->MstscUserPath);

	if (IsEmptyStr(dc->MstscParams) == false)
	{
		SetTextA(hWnd, E_PARAM, dc->MstscParams);
		Check(hWnd, C_ADDPARAM, true);
	}
	else
	{
		Check(hWnd, C_ADDPARAM, false);
	}

	Check(hWnd, C_PUBLIC, dc->MstscUsePublicSwitchForVer6);

	Check(hWnd, C_NO_FQDN, dc->MstscNoFqdn);

	Check(hWnd, C_CHECK_CERT, WideGetDontCheckCert(dc->Wide) ? false : true);

	Check(hWnd, C_VER2, dc->EnableVersion2);

	Check(hWnd, C_SHOW_THEEND, MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME));
	Check(hWnd, C_ENABLE_RELAX, MsRegReadInt(REG_CURRENT_USER, DU_REGKEY, DU_ENABLE_RELAX_KEY_NAME));

	Check(hWnd, C_MULTIDISPLAY, !dc->DisableMultiDisplay);

	Check(hWnd, C_LIMITED_FW, !dc->DisableLimitedFw);

	SetShow(hWnd, C_LIMITED_FW, Vars_ActivePatch_Exists("ThinFwMode") == false);

	if (Vars_ActivePatch_GetBool("ThinTelework_DisableOmakeFunctions"))
	{
		Hide(hWnd, C_SHOW_THEEND);
		Hide(hWnd, C_ENABLE_RELAX);
		Hide(hWnd, S_UX);
		Hide(hWnd, S_UX2);
	}

	DuOptionDlgInitProxyStr(hWnd, t);

	DuOptionDlgUpdate(hWnd, t);
}

// プロキシ文字列初期化
void DuOptionDlgInitProxyStr(HWND hWnd, DU_OPTION *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	SetText(hWnd, S_PROXY_CONFIG, GetProxyTypeStr(t->InternetSetting.ProxyType));
}

// コントロール更新
void DuOptionDlgUpdate(HWND hWnd, DU_OPTION *t)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (Vars_ActivePatch_GetBool("ThinTelework_EnforceStrongSecurity"))
	{
		if (MsIsVista() && MsIsAdmin())
		{
			// LGWAN 版で Windows Vista 以降で Administrators 権限の場合はユーザー指定
			// EXE 関係のコントロールを無効化する
			SetEnable(hWnd, C_USERPATH, false);
		}
	}

	SetEnable(hWnd, S_CHECK_CERT, IsChecked(hWnd, C_CHECK_CERT));

	SetEnable(hWnd, E_PATH, IsChecked(hWnd, C_USERPATH));
	SetEnable(hWnd, S_PATH, IsChecked(hWnd, C_USERPATH));
	SetEnable(hWnd, B_BROWSE, IsChecked(hWnd, C_USERPATH));

	SetEnable(hWnd, E_PARAM, IsChecked(hWnd, C_ADDPARAM));
	SetEnable(hWnd, S_PARAMS, IsChecked(hWnd, C_ADDPARAM));

	if (IsChecked(hWnd, C_USERPATH))
	{
		wchar_t tmp[MAX_PATH];

		GetTxt(hWnd, E_PATH, tmp, sizeof(tmp));
		
		if (UniIsEmptyStr(tmp))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, C_ADDPARAM))
	{
		wchar_t tmp[MAX_PATH];

		GetTxt(hWnd, E_PARAM, tmp, sizeof(tmp));

		if (UniIsEmptyStr(tmp))
		{
			b = false;
		}
	}

	SetEnable(hWnd, IDOK, b);
}

// OK ボタン
void DuOptionDlgOnOk(HWND hWnd, DU_OPTION *t)
{
	wchar_t tmp[MAX_PATH];
	DC *dc;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	dc = t->Du->Dc;

	// パラメータ検査
	if (IsChecked(hWnd, C_USERPATH))
	{
		GetTxt(hWnd, E_PATH, tmp, sizeof(tmp));
		UniTrim(tmp);

		if (IsFileExistsW(tmp) == false)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("DU_MSTSC_NOT_FOUND"), tmp);
			FocusEx(hWnd, E_PATH);
			return;
		}

		if (DcGetMstscVersion(tmp) == 0)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("DU_MSTSC_INVALID"), tmp);
			FocusEx(hWnd, E_PATH);
			return;
		}
	}

	// プロキシ設定
	DcSetInternetSetting(dc, &t->InternetSetting);

	// SSL 設定
	WideSetDontCheckCert(dc->Wide, IsChecked(hWnd, C_CHECK_CERT) ? false : true);

	// mstsc の場所
	if (IsChecked(hWnd, C_DOWNLOAD))
	{
		dc->MstscLocation = DC_MSTSC_DOWNLOAD;
	}
	else if (IsChecked(hWnd, C_USERPATH))
	{
		dc->MstscLocation = DC_MSTSC_USERPATH;
	}
	else
	{
		dc->MstscLocation = DC_MSTSC_SYSTEM32;
	}

	dc->EnableVersion2 = IsChecked(hWnd, C_VER2);

	GetTxt(hWnd, E_PATH, dc->MstscUserPath, sizeof(dc->MstscUserPath));
	UniTrim(dc->MstscUserPath);

	// パラメータ
	if (IsChecked(hWnd, C_ADDPARAM))
	{
		GetTxtA(hWnd, E_PARAM, dc->MstscParams, sizeof(dc->MstscParams));
		Trim(dc->MstscParams);
	}
	else
	{
		StrCpy(dc->MstscParams, sizeof(dc->MstscParams), "");
	}

	dc->MstscUsePublicSwitchForVer6 = IsChecked(hWnd, C_PUBLIC);

	dc->MstscNoFqdn = IsChecked(hWnd, C_NO_FQDN);

	dc->DisableMultiDisplay = !IsChecked(hWnd, C_MULTIDISPLAY);

	dc->DisableLimitedFw = !IsChecked(hWnd, C_LIMITED_FW);

	DcSaveConfig(dc);

	// お疲れ様でした
	MsRegWriteInt(REG_CURRENT_USER, DU_REGKEY, DU_SHOW_THEEND_KEY_NAME, IsChecked(hWnd, C_SHOW_THEEND));

	// リラックスモード
	MsRegWriteInt(REG_CURRENT_USER, DU_REGKEY, DU_ENABLE_RELAX_KEY_NAME, IsChecked(hWnd, C_ENABLE_RELAX));

	EndDialog(hWnd, 1);
}

// オプションダイアログプロシージャ
UINT DuOptionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_OPTION *t = (DU_OPTION *)param;
	wchar_t *ret;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuOptionDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PATH:
		case E_PARAM:
			DuOptionDlgUpdate(hWnd, t);
			break;
		}

		switch (wParam)
		{
		case B_PROXY:
			// プロキシ
			if (DgProxyDlg(hWnd, &t->InternetSetting))
			{
				DuOptionDlgInitProxyStr(hWnd, t);
			}
			break;

		case C_CHECK_CERT:
			// SSL
			DuOptionDlgUpdate(hWnd, t);
			break;

		case C_SYSTEM32:
		case C_DOWNLOAD:
		case C_USERPATH:
			DuOptionDlgUpdate(hWnd, t);

			if (IsChecked(hWnd, C_USERPATH))
			{
				FocusEx(hWnd, E_PATH);
			}
			break;

		case C_ADDPARAM:
			DuOptionDlgUpdate(hWnd, t);

			if (IsChecked(hWnd, C_ADDPARAM))
			{
				FocusEx(hWnd, E_PARAM);
			}
			break;

		case B_BROWSE:
			ret = OpenDlg(hWnd, _UU("DLG_EXE_FILES"), _UU("DU_MSTSC_OPEN_TITLE"));
			if (ret != NULL)
			{
				UniTrim(ret);
				SetText(hWnd, E_PATH, ret);
				FocusEx(hWnd, E_PATH);
				Free(ret);
			}
			break;

		case IDOK:
			DuOptionDlgOnOk(hWnd, t);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		return 1;
	}

	return 0;
}

// オプションダイアログ
void DuOptionDlg(HWND hWnd, DU_MAIN *t)
{
	DU_OPTION o;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));
	o.Du = t->Du;
	o.Main = t;

	Dialog(hWnd, D_DU_OPTION, DuOptionDlgProc, &o);
}

// PCID 一覧の設定
void DuMainDlgInitPcidCandidate(HWND hWnd, DU_MAIN *t)
{
	UINT i;
	LIST *c;

	c = t->Du->Dc->Candidate;

	SendMsg(hWnd, C_PCID, CB_RESETCONTENT, 0, 0);

	for (i = 0;i < LIST_NUM(c);i++)
	{
		CANDIDATE *item = LIST_DATA(c, i);

		if (UniIsEmptyStr(item->Str) == false)
		{
			CbAddStr(hWnd, C_PCID, item->Str, 0);
		}
	}

	CbSetHeight(hWnd, C_PCID, 20);
}

// 初期化
void DuMainDlgInit(HWND hWnd, DU_MAIN *t)
{
	HFONT h, h2;
	HMENU hMenu;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	t->hWnd = hWnd;

	hMenu = GetSystemMenu(hWnd, false);
	if (hMenu != NULL)
	{
		MsAppendMenu(hMenu, MF_ENABLED | MF_STRING, CMD_ABOUT, _UU("DU_MENU_ABOUT"));

		DrawMenuBar(hWnd);
	}

	FormatText(hWnd, 0,
		DESK_VERSION / 100, DESK_VERSION % 100,
		DESK_BUILD);

	Center2(hWnd);

	SetIcon(hWnd, 0, ICO_THINCLIENT);

	h = GetFont("Tahoma", 11, false, false, false, false);
	h2 = GetFont("Tahoma", 8, false, false, false, false);

	SetFont(hWnd, C_PCID, h);

	SetTextA(hWnd, E_SYSTEM, t->Du->Dc->Wide->wt->System);
	SetFont(hWnd, E_SYSTEM, h2);

	DuMainDlgInitPcidCandidate(hWnd, t);

	DuMainDlgUpdate(hWnd, t, false);

	// バナー初期化
	if (Rand32() % 2)
	{
		Show(hWnd, S_BANNER1);
		Hide(hWnd, S_BANNER2);
	}
	else
	{
		Show(hWnd, S_BANNER2);
		Hide(hWnd, S_BANNER1);
	}

	if (IsEmptyStr(_SS("DU_WEB_URL")))
	{
		Hide(hWnd, B_WEB);
	}

	SetTimer(hWnd, 1, 100, NULL);
	SetTimer(hWnd, 2, DU_BANNER_SWITCH_INTERVAL, NULL);

	t->Update = InitUpdateUiEx(_UU("PRODUCT_NAME_DESKCLIENT"), DI_PRODUCT_CLIENT_NAME, NULL, GetCurrentBuildDate(),
		CEDAR_BUILD, CEDAR_VER, NULL, false, t->Du->Dc->Wide->wt);
}

// コントロール更新
void DuMainDlgUpdate(HWND hWnd, DU_MAIN *t, bool forceEnable)
{
	bool b = true;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, C_PCID) && forceEnable == false)
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);
}

// OK ボタン
void DuMainDlgOnOk(HWND hWnd, DU_MAIN *t)
{
	char pcid[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	UINT i;
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	DisableUpdateUi(t->Update);

	GetTxtA(hWnd, C_PCID, pcid, sizeof(pcid));
	Trim(pcid);

	StrToUni(tmp, sizeof(tmp), pcid);

	AddCandidate(t->Du->Dc->Candidate, tmp, DU_CANDIDATE_MAX);
	Sort(t->Du->Dc->Candidate);

	DcSaveConfig(t->Du->Dc);

	i = CbFindStr(hWnd, C_PCID, tmp);
	if (i != INFINITE)
	{
		SendMsg(hWnd, C_PCID, CB_DELETESTRING, i, 0);
	}

	CbInsertStr(hWnd, C_PCID, 0, tmp, 0);

	CbSelect(hWnd, C_PCID, 0);

	StrCpy(t->Pcid, sizeof(t->Pcid), pcid);

	DuMainDlgSetControlEnabled(hWnd, false);

	DuConnectDlg(hWnd, t);

	DuMainDlgSetControlEnabled(hWnd, true);

	FocusEx(hWnd, C_PCID);
}

// コントロールの有効 / 無効の設定
void DuMainDlgSetControlEnabled(HWND hWnd, bool b)
{
	// 引数チェック
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, C_PCID, b);
	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, IDCANCEL, b);
	SetEnable(hWnd, B_OPTION, b);
	SetEnable(hWnd, B_SHARE, b);
	SetEnable(hWnd, B_WOL, b);
	SetEnable(hWnd, B_ERASE, b);
	SetEnable(hWnd, B_WEB, b);
	SetEnable(hWnd, E_SYSTEM, b);
	SetEnable(hWnd, S_PCID, b);
	SetEnable(hWnd, S_SYSTEM, b);

	if (b)
	{
		EnableClose(hWnd);
	}
	else
	{
		DisableClose(hWnd);
	}
	DoEvents(hWnd);
}

// 閉じる
void DuMainDlgOnClose(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	DcSaveConfig(t->Du->Dc);

	if (t->Update != NULL)
	{
		FreeUpdateUi(t->Update);
		t->Update = NULL;
	}

	EndDialog(hWnd, 0);
}

// バナー切り替え
void DuMainBanner(HWND hWnd, DU_MAIN *t)
{
	// 引数チェック
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (IsShow(hWnd, S_BANNER1))
	{
		Show(hWnd, S_BANNER2);
		Hide(hWnd, S_BANNER1);
	}
	else
	{
		Show(hWnd, S_BANNER1);
		Hide(hWnd, S_BANNER2);
	}
}

// メインダイアログプロシージャ
UINT DuMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	DU_MAIN *t = (DU_MAIN *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		DuMainDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case C_PCID:
			// 空欄状態から上下矢印を入力したときにOKが無効になるのを防止
			DuMainDlgUpdate(hWnd, t, HIWORD(wParam)==CBN_SELCHANGE);
			break;

		case S_BANNER1:
		case S_BANNER2:
			switch (HIWORD(wParam))
			{
			case STN_CLICKED:
				MsExecute(_SS("SE_BANNER_URL"), NULL);
				break;
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// 接続
			if (IsEnable(hWnd, IDOK))
			{
				DuMainDlgOnOk(hWnd, t);
			}
			break;

		case IDCANCEL:
			// キャンセル
			Close(hWnd);
			break;

		case B_OPTION:
			// オプション
			DuOptionDlg(hWnd, t);
			break;

		case B_SHARE:
			// 共有
			DuShareDlg(hWnd, t);
			break;

		case B_ERASE:
			// 履歴の消去
			if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("DU_ERASE")) == IDYES)
			{
				DcEraseCandidate(t->Du->Dc);
				DcClearAdvAuthList(t->Du->Dc);

				DcSaveConfig(t->Du->Dc);

				CbReset(hWnd, C_PCID);
				SetTextA(hWnd, C_PCID, "");

				Focus(hWnd, C_PCID);
			}
			break;

		case B_WOL:
			// Wake on LAN
			DuWoLDlg(hWnd, t);

			DuMainDlgInitPcidCandidate(hWnd, t);
			break;

		case B_WEB:
			// Web browser
			ShellExecute(hWnd, "open", _SS("DU_WEB_URL"), NULL, NULL, SW_SHOW);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			if (IsEmptyStr(t->Du->AutoConnectPcid) == false)
			{
				// 自動接続
				SetTextA(hWnd, C_PCID, t->Du->AutoConnectPcid);
				SendMsg(hWnd, 0, WM_COMMAND, IDOK, 0);
			}
			break;

		case 2:
			DuMainBanner(hWnd, t);
			break;
		}
		break;

	case WM_SYSCOMMAND:
		switch (LOWORD(wParam))
		{
		case CMD_ABOUT:
			// バージョン情報
			AboutEx(hWnd, t->Du->Cedar, _UU("PRODUCT_NAME_DESKCLIENT"), t->Update);
			break;
		}
		break;

	case WM_CLOSE:
		DuMainDlgOnClose(hWnd, t);
		return 1;
	}

	return 0;
}

// メイン
void DuMain(DU *du)
{
	DU_MAIN t;
	// 引数チェック
	if (du == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Du = du;

	Dialog(NULL, D_DU_MAIN, DuMainDlgProc, &t);
}

// GUI の実行
void DUExec()
{
	DU *du = ZeroMalloc(sizeof(DU));
	char *s,*s2;
	bool localconfig = false;

	InitWinUi(_UU("DU_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	du->Cedar = NewCedar(NULL, NULL);

	s = s2 = GetCommandLineStr();

	if (InStr(s, "/govfw"))
	{
		// 完全閉域化ファイアウォール
		DuGovFw2Main();
	}
	else
	{
		// /local オプションで設定ファイルを実行ファイルのディレクトリに保存
		if (StrCmpi(s,"/local") == 0 || StartWith(s,"/local "))
		{
			localconfig = true;
			s+=6;
		}

		if (IsFileExists(DU_LOCALCONFIG_FILENAME))
		{
			localconfig = true;
		}

		if (IsEmptyStr(s) == false)
		{
			Trim(s);
			StrCpy(du->AutoConnectPcid, sizeof(du->AutoConnectPcid), s);
		}

	
		du->Dc = NewDc(localconfig);

		// メイン
		DuMain(du);

		FreeDc(du->Dc);
	}

	ReleaseCedar(du->Cedar);

	FreeWinUi();

	Free(du);

	Free(s2);
}



// Initialization of the API
bool DuInitWfpApi()
{
	if (du_wfp_api != NULL)
	{
		return true;
	}

	if (du_wfp_dll == NULL)
	{
		du_wfp_dll = LoadLibraryA("FWPUCLNT.DLL");
	}

	if (du_wfp_dll == NULL)
	{
		return false;
	}

	du_wfp_api = malloc(sizeof(DU_WFP_FUNCTIONS));
	Zero(du_wfp_api, sizeof(DU_WFP_FUNCTIONS));

	du_wfp_api->FwpmEngineOpen0 = 
		(DWORD (__stdcall *)(const wchar_t *,UINT32,SEC_WINNT_AUTH_IDENTITY_W *,const FWPM_SESSION0 *,HANDLE *))
		GetProcAddress(du_wfp_dll, "FwpmEngineOpen0");

	du_wfp_api->FwpmEngineClose0 =
		(DWORD (__stdcall *)(HANDLE))
		GetProcAddress(du_wfp_dll, "FwpmEngineClose0");

	du_wfp_api->FwpmFreeMemory0 =
		(void (__stdcall *)(void **))
		GetProcAddress(du_wfp_dll, "FwpmFreeMemory0");

	du_wfp_api->FwpmFilterAdd0 =
		(DWORD (__stdcall *)(HANDLE,const FWPM_FILTER0 *,PSECURITY_DESCRIPTOR,UINT64 *))
		GetProcAddress(du_wfp_dll, "FwpmFilterAdd0");

	du_wfp_api->IPsecSaContextCreate0 =
		(DWORD (__stdcall *)(HANDLE,const IPSEC_TRAFFIC0 *,UINT64 *,UINT64 *))
		GetProcAddress(du_wfp_dll, "IPsecSaContextCreate0");

	du_wfp_api->IPsecSaContextGetSpi0 =
		(DWORD (__stdcall *)(HANDLE,UINT64,const IPSEC_GETSPI0 *,IPSEC_SA_SPI *))
		GetProcAddress(du_wfp_dll, "IPsecSaContextGetSpi0");

	du_wfp_api->IPsecSaContextAddInbound0 =
		(DWORD (__stdcall *)(HANDLE,UINT64,const IPSEC_SA_BUNDLE0 *))
		GetProcAddress(du_wfp_dll, "IPsecSaContextAddInbound0");

	du_wfp_api->IPsecSaContextAddOutbound0 =
		(DWORD (__stdcall *)(HANDLE,UINT64,const IPSEC_SA_BUNDLE0 *))
		GetProcAddress(du_wfp_dll, "IPsecSaContextAddOutbound0");

	du_wfp_api->FwpmCalloutAdd0 =
		(DWORD (__stdcall *)(HANDLE,const FWPM_CALLOUT0 *,PSECURITY_DESCRIPTOR,UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmCalloutAdd0");

	du_wfp_api->FwpmSubLayerAdd0 =
		(DWORD(__stdcall *)(HANDLE, const FWPM_SUBLAYER0 *, PSECURITY_DESCRIPTOR))
		GetProcAddress(du_wfp_dll, "FwpmSubLayerAdd0");

	du_wfp_api->FwpmProviderAdd0 =
		(DWORD(__stdcall *)(HANDLE, const FWPM_PROVIDER0 *, PSECURITY_DESCRIPTOR))
		GetProcAddress(du_wfp_dll, "FwpmProviderAdd0");

	du_wfp_api->FwpmGetAppIdFromFileName0 =
		(DWORD(__stdcall *)(PCWSTR, FWP_BYTE_BLOB **))
		GetProcAddress(du_wfp_dll, "FwpmGetAppIdFromFileName0");

	du_wfp_api->FwpmNetEventCreateEnumHandle0 =
		(DWORD(__stdcall *)(HANDLE, const FWPM_NET_EVENT_ENUM_TEMPLATE0 *, HANDLE *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventCreateEnumHandle0");

	du_wfp_api->FwpmNetEventEnum0 =
		(DWORD(__stdcall *)(HANDLE, HANDLE, UINT32, FWPM_NET_EVENT1 ***, UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventEnum0");

	du_wfp_api->FwpmNetEventEnum1 =
		(DWORD(__stdcall *)(HANDLE, HANDLE, UINT32, FWPM_NET_EVENT1 ***, UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventEnum1");

	du_wfp_api->FwpmNetEventEnum2 =
		(DWORD(__stdcall *)(HANDLE, HANDLE, UINT32, FWPM_NET_EVENT1 ***, UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventEnum2");

	du_wfp_api->FwpmNetEventEnum3 =
		(DWORD(__stdcall *)(HANDLE, HANDLE, UINT32, FWPM_NET_EVENT1 ***, UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventEnum3");

	du_wfp_api->FwpmNetEventEnum4 =
		(DWORD(__stdcall *)(HANDLE, HANDLE, UINT32, FWPM_NET_EVENT1 ***, UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventEnum4");

	du_wfp_api->FwpmNetEventEnum5 =
		(DWORD(__stdcall *)(HANDLE, HANDLE, UINT32, FWPM_NET_EVENT1 ***, UINT32 *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventEnum5");

	du_wfp_api->FwpmNetEventDestroyEnumHandle0 =
		(DWORD(__stdcall *)(HANDLE, HANDLE))
		GetProcAddress(du_wfp_dll, "FwpmNetEventDestroyEnumHandle0");

	du_wfp_api->FwpmEngineGetOption0 =
		(DWORD(__stdcall *)(HANDLE, FWPM_ENGINE_OPTION, FWP_VALUE0 **))
		GetProcAddress(du_wfp_dll, "FwpmEngineGetOption0");

	du_wfp_api->FwpmEngineSetOption0 =
		(DWORD(__stdcall *)(HANDLE, FWPM_ENGINE_OPTION, const FWP_VALUE0 *))
		GetProcAddress(du_wfp_dll, "FwpmEngineSetOption0");

	du_wfp_api->FwpmNetEventSubscribe0 =
		(DWORD(__stdcall *)(HANDLE, const FWPM_NET_EVENT_SUBSCRIPTION0 *, FWPM_NET_EVENT_CALLBACK0, void *, HANDLE *))
		GetProcAddress(du_wfp_dll, "FwpmNetEventSubscribe0");
	
	du_wfp_api->FwpmNetEventUnsubscribe0 =
		(DWORD(__stdcall *)(HANDLE, HANDLE))
		GetProcAddress(du_wfp_dll, "FwpmNetEventUnsubscribe0");

	du_wfp_api->FwpmLayerGetByKey0 =
		(DWORD(__stdcall *)(HANDLE, const GUID *, FWPM_LAYER0 **))
		GetProcAddress(du_wfp_dll, "FwpmLayerGetByKey0");

	if (du_wfp_api->FwpmEngineOpen0 == NULL ||
		du_wfp_api->FwpmEngineClose0 == NULL ||
		du_wfp_api->FwpmFreeMemory0 == NULL ||
		du_wfp_api->FwpmFilterAdd0 == NULL ||
		du_wfp_api->IPsecSaContextCreate0 == NULL ||
		du_wfp_api->IPsecSaContextGetSpi0 == NULL ||
		du_wfp_api->IPsecSaContextAddInbound0 == NULL ||
		du_wfp_api->IPsecSaContextAddOutbound0 == NULL ||
		du_wfp_api->FwpmCalloutAdd0 == NULL ||
		du_wfp_api->FwpmSubLayerAdd0 == NULL ||
		du_wfp_api->FwpmProviderAdd0 == NULL ||
		du_wfp_api->FwpmGetAppIdFromFileName0 == NULL ||
		du_wfp_api->FwpmEngineGetOption0 == NULL ||
		du_wfp_api->FwpmEngineSetOption0 == NULL ||
		du_wfp_api->FwpmLayerGetByKey0 == NULL ||
		false
		)
	{
		free(du_wfp_api);
		du_wfp_api = NULL;
		return false;
	}

	return true;
}

UINT DuWfpGetLayerIdFromLayerKey(HANDLE hEngine, const GUID *layer_key)
{
	if (hEngine == NULL || layer_key == NULL)
	{
		return INFINITE;
	}

	FWPM_LAYER0 *t = NULL;

	UINT ret = du_wfp_api->FwpmLayerGetByKey0(hEngine, layer_key, &t);

	if (ret)
	{
		return INFINITE;
	}

	UINT layer_id = INFINITE;

	if (t != NULL)
	{
		layer_id = t->layerId;

		du_wfp_api->FwpmFreeMemory0(&t);
	}

	return layer_id;
}

void CALLBACK DuWfpLogSubscriberCallback(void *ctx, const FWPM_NET_EVENT1 *ev)
{
	DU_WFP_LOG *g = (DU_WFP_LOG *)ctx;
	if (g == NULL)
	{
		return;
	}

	UINT64 tick = Tick64();

	wchar_t key[2048];

	MS_THINFW_ENTRY_BLOCK b = CLEAN;

	if (DuWfpNetEvent1ToStructure(g, (void *)ev, &b, key, sizeof(key)))
	{
		LockList(g->CurrentEntryList);
		{
			AddOrRenewDiffEntry(g->CurrentEntryList, key, &b, sizeof(b), MS_THINFW_ENTRY_TYPE_BLOCK, tick);

			DuWfpLogGc(g, tick, false);
		}
		UnlockList(g->CurrentEntryList);
	}
}

UINT DuWfpLogGc(DU_WFP_LOG *g, UINT64 tick, bool force)
{
	if (g == NULL)
	{
		return 0;
	}

	if (tick == 0)
	{
		tick = Tick64();
	}

	UINT num_deleted = 0;

	if (force || ((g->LastGcTick + (UINT64)g->Settings.EntryExpireMsec) < tick))
	{
		UINT64 threshold = 0;

		if (tick > (UINT64)g->Settings.EntryExpireMsec)
		{
			threshold = tick - (UINT64)g->Settings.EntryExpireMsec;
		}

		num_deleted = DeleteOldDiffEntry(g->CurrentEntryList, threshold);

		g->LastGcTick = tick;

		//Debug("GC: DeleteOldDiffEntry: %u, current = %u\n", num_deleted, LIST_NUM(g->CurrentEntryList));
	}

	return num_deleted;
}

bool DuWfpNetEvent1ToStructure(DU_WFP_LOG *g, void *event, MS_THINFW_ENTRY_BLOCK *dst, wchar_t *key, UINT key_size)
{
	FWPM_NET_EVENT1 *ev = (FWPM_NET_EVENT1 *)event;

	Zero(dst, sizeof(MS_THINFW_ENTRY_BLOCK));
	if (g == NULL || ev == NULL || dst == NULL || key == NULL)
	{
		return false;
	}

	if (ev->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP)
	{
		return false;
	}

	FWPM_NET_EVENT_HEADER1 *h = &ev->header;

	if (
		ev->classifyDrop != NULL &&
		ev->classifyDrop->isLoopback == false &&
		(ev->classifyDrop->msFwpDirection == FWP_DIRECTION_INBOUND || ev->classifyDrop->msFwpDirection == FWP_DIRECTION_OUTBOUND) &&
		(h->flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) &&
		(h->flags & FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) &&
		(h->flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) &&
		(h->flags & FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) &&
		(h->flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) &&
		(h->flags & FWPM_NET_EVENT_FLAG_IP_VERSION_SET) &&
		(h->ipVersion == FWP_IP_VERSION_V4 || h->ipVersion == FWP_IP_VERSION_V6) &&
		(h->ipProtocol == IP_PROTO_TCP || h->ipProtocol == IP_PROTO_UDP) &&
		(ev->classifyDrop->layerId == g->LayerId_IPv4_Receive ||
			ev->classifyDrop->layerId == g->LayerId_IPv4_Send || 
			ev->classifyDrop->layerId == g->LayerId_IPv6_Receive || 
			ev->classifyDrop->layerId == g->LayerId_IPv6_Send)
		)
	{
		MS_THINFW_ENTRY_BLOCK b = CLEAN;

		b.IsReceive = (ev->classifyDrop->layerId == g->LayerId_IPv4_Receive || ev->classifyDrop->layerId == g->LayerId_IPv6_Receive);
		b.Protocol = h->ipProtocol;

		if (h->ipVersion == FWP_IP_VERSION_V4)
		{
			UINTToIP(&b.LocalIP, Endian32(h->localAddrV4));
			UINTToIP(&b.RemoteIP, Endian32(h->remoteAddrV4));
		}
		else
		{
			InAddrToIP6(&b.LocalIP, (struct in6_addr *)&h->localAddrV6);
			InAddrToIP6(&b.RemoteIP, (struct in6_addr *)&h->remoteAddrV6);
		}

		b.LocalPort = h->localPort;
		b.RemotePort = h->remotePort;

		if (h->flags & FWPM_NET_EVENT_FLAG_APP_ID_SET)
		{
			Copy(b.ProcessExeName, h->appId.data, MIN(h->appId.size, sizeof(b.ProcessExeName) - 4));
		}
		else
		{
			UniStrCpy(b.ProcessExeName, sizeof(b.ProcessExeName), L"(unknown app)");
		}

		UniStrCpy(b.Username, sizeof(b.Username), L"(unknown user)");
		UniStrCpy(b.DomainName, sizeof(b.DomainName), L".");

		SYSTEMTIME st = CLEAN;
		if (FileTimeToSystemTime(&h->timeStamp, &st))
		{
			b.SystemTime = SystemToUINT64(&st);
		}

		if (h->flags & FWPM_NET_EVENT_FLAG_USER_ID_SET && h->userId != NULL)
		{
			MS_SID_INFO *info = NULL;

			info = MsGetUsernameFromSid2(g->MsSidCache, h->userId);

			if (info != NULL)
			{
				UniStrCpy(b.Username, sizeof(b.Username), info->Username);
				UniStrCpy(b.DomainName, sizeof(b.DomainName), info->DomainName);
			}
		}

		UINT key_local_port = b.LocalPort;
		UINT key_remote_port = b.RemotePort;

		if (b.IsReceive)
		{
			// TCP or UDP server mode: Do not store remote port on the key string
			key_remote_port = 0;
		}
		else
		{
			// TCP or UDP client mode: Do not store local port on the key string
			key_local_port = 0;
		}

		UniFormat(key, key_size,
			L"WPF_DROP_LOG %r %u %r %u %u %u %s %s\\%s",
			&b.RemoteIP, key_remote_port,
			&b.LocalIP, key_local_port,
			b.IsReceive, b.Protocol,
			b.ProcessExeName, b.Username, b.DomainName);

		//UniPrint(L"%s\n", key);

		Copy(dst, &b, sizeof(b));

		return true;
	}

	return false;
}

DU_WFP_LOG *DuWfpStartLog2(DU_WFP_LOG_SETTINGS *settings)
{
	if (settings == NULL)
	{
		return NULL;
	}

	if (DuInitWfpApi() == false)
	{
		return NULL;
	}

	if (MsIsAdmin() == false)
	{
		return NULL;
	}

	if (du_wfp_api->FwpmNetEventSubscribe0 == NULL ||
		du_wfp_api->FwpmNetEventUnsubscribe0 == NULL)
	{
		return NULL;
	}

	FWPM_SESSION0 session = CLEAN;

	HANDLE engine = NULL;

	UINT ret = du_wfp_api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &engine);
	if (ret)
	{
		Debug("DuWfpStartLog: FwpmEngineOpen0 Failed. ret = 0x%X\n", ret);
		return false;
	}

	DU_WFP_LOG *g = ZeroMalloc(sizeof(DU_WFP_LOG));

	Copy(&g->Settings, settings, sizeof(DU_WFP_LOG_SETTINGS));

	if (g->Settings.EntryExpireMsec == 0)
	{
		g->Settings.EntryExpireMsec = DU_WFP_LOG_ENTRY_EXPIRES_MSEC_DEFAULT;
	}

	g->CurrentEntryList = NewDiffList();

	g->Engine = engine;

	g->LayerId_IPv4_Receive = DuWfpGetLayerIdFromLayerKey(g->Engine, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
	g->LayerId_IPv4_Send = DuWfpGetLayerIdFromLayerKey(g->Engine, &FWPM_LAYER_ALE_AUTH_CONNECT_V4);

	g->LayerId_IPv6_Receive = DuWfpGetLayerIdFromLayerKey(g->Engine, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
	g->LayerId_IPv6_Send = DuWfpGetLayerIdFromLayerKey(g->Engine, &FWPM_LAYER_ALE_AUTH_CONNECT_V6);

	g->MsSidCache = MsNewSidToUsernameCache();

	FWPM_NET_EVENT_SUBSCRIPTION0 t = CLEAN;

	ret = du_wfp_api->FwpmNetEventSubscribe0(g->Engine, &t, DuWfpLogSubscriberCallback, g, &g->Subscription);
	if (ret)
	{
		Debug("DuWfpStartLog: FwpmNetEventSubscribe0 Failed. ret = 0x%X\n", ret);

		DuWfpStopLog2(g);

		return false;
	}

	return g;
}

void DuWfpStopLog2(DU_WFP_LOG *g)
{
	UINT ret = 0;

	if (g == NULL)
	{
		return;
	}

	if (g->Subscription != NULL)
	{
		ret = du_wfp_api->FwpmNetEventUnsubscribe0(g->Engine, g->Subscription);

		if (ret)
		{
			Debug("DuWfpStartLog: FwpmNetEventSubscribe0 Failed. ret = 0x%X\n", ret);
		}
	}

	MsFreeSidToUsernameCache(g->MsSidCache);

	du_wfp_api->FwpmEngineClose0(g->Engine);

	FreeDiffList(g->CurrentEntryList);

	Free(g);
}

bool DuWfpCreateProvider(HANDLE hEngine, GUID *created_guid, char *name)
{
	if (created_guid == NULL)
	{
		return false;
	}

	Zero(created_guid, sizeof(GUID));

	if (IsEmptyStr(name))
	{
		name = "untitled provider";
	}

	wchar_t tmp[MAX_PATH] = CLEAN;
	StrToUni(tmp, sizeof(tmp), name);

	FWPM_PROVIDER0 t = CLEAN;
	t.displayData.description = tmp;
	t.displayData.name = tmp;

	MsNewGuid(&t.providerKey);

	UINT ret = du_wfp_api->FwpmProviderAdd0(hEngine, &t, NULL);

	if (ret)
	{
		Debug("FwpmProviderAdd0 Failed: 0x%X\n", ret);
		return false;
	}

	Copy(created_guid, &t.providerKey, sizeof(GUID));

	return true;
}

bool DuWfpCreateSublayer(HANDLE hEngine, GUID *created_guid, GUID *provider_guid, char *name, USHORT weight)
{
	if (created_guid == NULL || provider_guid == NULL)
	{
		return false;
	}

	if (IsEmptyStr(name))
	{
		name = "untitled sublayer";
	}

	wchar_t tmp[MAX_PATH] = CLEAN;
	StrToUni(tmp, sizeof(tmp), name);

	FWPM_SUBLAYER0 t = CLEAN;
	t.displayData.description = tmp;
	t.displayData.name = tmp;
	t.providerKey = provider_guid;
	t.weight = weight;

	MsNewGuid(&t.subLayerKey);

	UINT ret = du_wfp_api->FwpmSubLayerAdd0(hEngine, &t, NULL);

	if (ret)
	{
		Debug("FwpmSubLayerAdd0 Failed: 0x%X\n", ret);
		return false;
	}

	Copy(created_guid, &t.subLayerKey, sizeof(GUID));

	return true;
}

void DuFwpAddTrustedExe(HANDLE hEngine, GUID *provider, GUID *sublayer, UINT index, wchar_t *exe, UINT allowed_directions, bool disable_wow)
{
	if (exe == NULL)
	{
		return;
	}

	FWP_BYTE_BLOB *this_app_id = NULL;

	void *wow = NULL;
	
	if (disable_wow)
	{
		MsDisableWow64FileSystemRedirection();
	}

	if (du_wfp_api->FwpmGetAppIdFromFileName0(exe, &this_app_id))
	{
		this_app_id = NULL;
	}

	MsRestoreWow64FileSystemRedirection(wow);

	if (this_app_id != NULL)
	{
		wchar_t name[MAX_SIZE] = CLEAN;

		UINT i, j, k;
		for (i = 0;i < 3;i++) // transport protocol (TCP, UDP, ICMP)
		{
			for (j = 0;j < 2;j++) // network protocol (IPv4, IPv6)
			{
				for (k = 0;k < 2;k++) // direction (IN, OUT)
				{
					UINT c_index = 0;
					FWPM_FILTER_CONDITION0 c[10] = CLEAN;

					UniFormat(name, sizeof(name), L"_ThinFW ACL %04u: trusted_exe (%u-%u-%u): %s", index, i, j, k, exe);

					UINT flag_exclude_bits = 0;

					// Exclude loopback
					flag_exclude_bits |= FWP_CONDITION_FLAG_IS_LOOPBACK;

					// Exclude this app
					if (this_app_id != NULL)
					{
						c[c_index].fieldKey = FWPM_CONDITION_ALE_APP_ID;
						c[c_index].matchType = FWP_MATCH_EQUAL;
						c[c_index].conditionValue.type = FWP_BYTE_BLOB_TYPE;
						c[c_index].conditionValue.byteBlob = this_app_id;
						c_index++;
					}

					// Protocol
					c[c_index].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
					c[c_index].matchType = FWP_MATCH_EQUAL;
					c[c_index].conditionValue.type = FWP_UINT8;

					UINT proto = 0;
					switch (i)
					{
					case 0:
						proto = IP_PROTO_TCP;
						break;
					case 1:
						proto = IP_PROTO_UDP;
						break;
					case 2:
						proto = j == 0 ? IP_PROTO_ICMPV4 : IP_PROTO_ICMPV6;
						break;
					}

					c[c_index].conditionValue.uint8 = proto;
					c_index++;

					FWPM_FILTER0 filter = CLEAN;
					UINT64 weight = ((UINT64)~((UINT64)0)) - (UINT64)index;

					Zero(&filter, sizeof(filter));
					filter.flags = 0;

					if (k == 0)
					{
						// Direction: In
						filter.layerKey = j == 0 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
					}
					else
					{
						// Direction: Out
						filter.layerKey = j == 0 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
					}

					if (sublayer != NULL)
					{
						filter.subLayerKey = *sublayer;
					}
					if (provider != NULL)
					{
						filter.providerKey = provider;
					}
					filter.weight.type = FWP_UINT64;
					filter.weight.uint64 = &weight;
					filter.action.type = FWP_ACTION_PERMIT;
					filter.displayData.name = name;

					filter.filterCondition = c;
					filter.numFilterConditions = c_index;

					bool ok = false;

					if (k == 0)
					{
						// IN
						if (allowed_directions & FW_PARSED_ACCESS_JITTER_ALLOW_SERVER)
						{
							ok = true;
						}
					}
					else if (k == 1)
					{
						// OUT
						if (allowed_directions & FW_PARSED_ACCESS_JITTER_ALLOW_CLIENT)
						{
							ok = true;
						}
					}

					if (ok)
					{
						UINT ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
						if (ret)
						{
							Debug("DuFwpAddTrustedExe: FwpmFilterAdd0 Failed: 0x%X\n", ret);
						}
					}
				}
			}
		}
	}

	if (this_app_id != NULL)
	{
		du_wfp_api->FwpmFreeMemory0(&this_app_id);
	}
}

void DuFwpAddAccess(HANDLE hEngine, GUID *provider, GUID *sublayer, UINT index, ACCESS *a)
{
	if (a == NULL)
	{
		return;
	}

	FWPM_FILTER0 filter = CLEAN;
	UINT64 weight = ((UINT64)~((UINT64)0)) - (UINT64)index;
	wchar_t name[MAX_SIZE] = CLEAN;
	UINT ret;
	FWPM_FILTER_CONDITION0 c[10] = CLEAN;
	bool isv4 = !a->IsIPv6;

	FWP_RANGE0 remote_port_range = CLEAN;
	FWP_RANGE0 local_port_range = CLEAN;

	UniFormat(name, sizeof(name), L"_ThinFW ACL %04u", index);

	if (UniIsFilledStr(a->Note))
	{
		UniStrCat(name, sizeof(name), L": ");
		UniStrCat(name, sizeof(name), a->Note);
	}

	UINT c_index = 0;

	UINT flag_exclude_bits = 0;

	// Exclude loopback
	flag_exclude_bits |= FWP_CONDITION_FLAG_IS_LOOPBACK;

	if (a->Established == false)
	{
		// Only new session packets
		flag_exclude_bits |= FWP_CONDITION_FLAG_IS_REAUTHORIZE;
	}

	if (flag_exclude_bits != 0)
	{
		c[c_index].fieldKey = FWPM_CONDITION_FLAGS;
		c[c_index].matchType = FWP_MATCH_FLAGS_NONE_SET;
		c[c_index].conditionValue.type = FWP_UINT32;
		c[c_index].conditionValue.uint32 = flag_exclude_bits;
		c_index++;
	}

	// Protocol
	c[c_index].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	c[c_index].matchType = FWP_MATCH_EQUAL;
	c[c_index].conditionValue.type = FWP_UINT8;
	c[c_index].conditionValue.uint8 = a->Protocol;
	c_index++;

	// Remote IP
	FWP_V4_ADDR_AND_MASK subnetv4 = CLEAN;
	FWP_V6_ADDR_AND_MASK subnetv6 = CLEAN;

	if (isv4)
	{
		subnetv4.addr = Endian32(a->DestIpAddress);
		subnetv4.mask = Endian32(a->DestSubnetMask);
	}
	else
	{
		Copy(subnetv6.addr, a->DestIpAddress6.Value, 16);
		IP tmp = CLEAN;
		IPv6AddrToIP(&tmp, &a->DestSubnetMask6);
		subnetv6.prefixLength = SubnetMaskToInt6(&tmp);
	}

	c[c_index].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	c[c_index].matchType = FWP_MATCH_EQUAL;
	c[c_index].conditionValue.type = isv4 ? FWP_V4_ADDR_MASK : FWP_V6_ADDR_MASK;

	if (isv4)
	{
		c[c_index].conditionValue.v4AddrMask = &subnetv4;
	}
	else
	{
		c[c_index].conditionValue.v6AddrMask = &subnetv6;
	}
	c_index++;

	if (a->Protocol == IP_PROTO_TCP || a->Protocol == IP_PROTO_UDP)
	{
		// Remote Port
		remote_port_range.valueLow.type = FWP_UINT16;
		remote_port_range.valueLow.uint16 = a->DestPortStart;
		remote_port_range.valueHigh.type = FWP_UINT16;
		remote_port_range.valueHigh.uint16 = a->DestPortEnd;

		c[c_index].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		c[c_index].matchType = FWP_MATCH_RANGE;
		c[c_index].conditionValue.type = FWP_RANGE_TYPE;
		c[c_index].conditionValue.rangeValue = &remote_port_range;
		c_index++;

		// Local Port
		local_port_range.valueLow.type = FWP_UINT16;
		local_port_range.valueLow.uint16 = a->SrcPortStart;
		local_port_range.valueHigh.type = FWP_UINT16;
		local_port_range.valueHigh.uint16 = a->SrcPortEnd;

		c[c_index].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
		c[c_index].matchType = FWP_MATCH_RANGE;
		c[c_index].conditionValue.type = FWP_RANGE_TYPE;
		c[c_index].conditionValue.rangeValue = &local_port_range;
		c_index++;
	}

	Zero(&filter, sizeof(filter));
	filter.flags = 0;
	if (a->Active)
	{
		// Direction: In
		filter.layerKey = isv4 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
	}
	else
	{
		// Direction: Out
		filter.layerKey = isv4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	}
	if (sublayer != NULL)
	{
		filter.subLayerKey = *sublayer;
	}
	if (provider != NULL)
	{
		filter.providerKey = provider;
	}
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = &weight;
	filter.action.type = a->Discard ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
	filter.displayData.name = name;

	filter.filterCondition = c;
	filter.numFilterConditions = c_index;

	ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
	if (ret)
	{
		Debug("DuFwpAddAccess: FwpmFilterAdd0 Failed: 0x%X\n", ret);
	}
}

// Add ACL rule with port
void DuWfpAddPortAcl(HANDLE hEngine, bool is_in, bool ipv6, UCHAR protocol, UINT port, UINT index, bool permit)
{
	FWPM_FILTER0 filter;
	UINT64 weight = ((UINT64)~((UINT64)0)) - (UINT64)index;
	wchar_t name[256];
	UINT ret;
	FWPM_FILTER_CONDITION0 c[2];
	bool isv4 = !ipv6;

	UniFormat(name, sizeof(name), L"DU_DuWfpAddPortAcl_%u", index);

	Zero(c, sizeof(c));
	c[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
	c[0].matchType = FWP_MATCH_EQUAL;
	c[0].conditionValue.type = FWP_UINT16;
	c[0].conditionValue.uint16 = port;

	c[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
	c[1].matchType = FWP_MATCH_EQUAL;
	c[1].conditionValue.type = FWP_UINT8;
	c[1].conditionValue.uint8 = protocol;

	Zero(&filter, sizeof(filter));
	filter.flags = 0;
	if (is_in)
	{
		filter.layerKey = isv4 ? FWPM_LAYER_INBOUND_TRANSPORT_V4 : FWPM_LAYER_INBOUND_TRANSPORT_V6;
	}
	else
	{
		filter.layerKey = isv4 ? FWPM_LAYER_OUTBOUND_TRANSPORT_V4 : FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
	}
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = &weight;
	filter.action.type = permit ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
	filter.displayData.name = name;

	filter.filterCondition = c;
	filter.numFilterConditions = 2;

	ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
	if (ret)
	{
		Debug("DuWfpAddPortAcl: FwpmFilterAdd0 Failed: 0x%X\n", ret);
	}
}

// Add ACL rule with IP
void DuWfpAddIpAcl(HANDLE hEngine, bool is_in, IP *ip, IP *mask, UINT index, bool permit)
{
	FWPM_FILTER0 filter;
	UINT64 weight = ((UINT64)~((UINT64)0)) - (UINT64)index;
	wchar_t name[256];
	UINT ret;
	FWPM_FILTER_CONDITION0 c;
	FWP_V4_ADDR_AND_MASK subnetv4;
	FWP_V6_ADDR_AND_MASK subnetv6;

	bool isv4 = false;

	if (IsIP4(ip) == false || IsIP4(mask) == false)
	{
		if (IsIP6(ip) == false || IsIP6(mask) == false)
		{
			return;
		}
	}

	isv4 = IsIP4(ip);

	UniFormat(name, sizeof(name), L"DU_DuWfpAddIpAcl_%u", index);

	Zero(&subnetv4, sizeof(subnetv4));
	if (isv4)
	{
		subnetv4.addr = Endian32(IPToUINT(ip));
		subnetv4.mask = Endian32(IPToUINT(mask));
	}

	Zero(&subnetv6, sizeof(subnetv6));
	if (isv4 == false)
	{
		Copy(subnetv6.addr, ip->ipv6_addr, 16);
		subnetv6.prefixLength = SubnetMaskToInt6(mask);
	}

	Zero(&c, sizeof(c));
	c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	c.matchType = FWP_MATCH_EQUAL;
	c.conditionValue.type = isv4 ? FWP_V4_ADDR_MASK : FWP_V6_ADDR_MASK;

	if (isv4)
	{
		c.conditionValue.v4AddrMask = &subnetv4;
	}
	else
	{
		c.conditionValue.v6AddrMask = &subnetv6;
	}

	Zero(&filter, sizeof(filter));
	filter.flags = 0;

	if (is_in)
	{
		filter.layerKey = isv4 ? FWPM_LAYER_INBOUND_TRANSPORT_V4 : FWPM_LAYER_INBOUND_TRANSPORT_V6;
	}
	else
	{
		filter.layerKey = isv4 ? FWPM_LAYER_OUTBOUND_TRANSPORT_V4 : FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
	}

	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = &weight;
	filter.action.type = permit ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
	filter.displayData.name = name;

	filter.filterCondition = &c;
	filter.numFilterConditions = 1;

	ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
	if (ret)
	{
		Debug("DuWfpAddIpAcl: FwpmFilterAdd0 Failed: 0x%X\n", ret);
	}
}

void DuWfpTest()
{
	FWPM_SESSION0 session;
	UINT ret;
	HANDLE hEngine;
	FWPM_FILTER0 filter;
	UINT64 weight = ((UINT64)~((UINT64)0));
	UINT64 FilterIPv4Id = 0;

	DuInitWfpApi();

	// Open the WFP (Dynamic Session)
	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	ret = du_wfp_api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
	if (ret)
	{
		Debug("FwpmEngineOpen0 Failed.\n");
		return;
	}

	if (false)
	{
	}
	else
	{

		// Create the Filter (IPv4)
		Zero(&filter, sizeof(filter));
		filter.flags = 0;
		filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
		filter.weight.type = FWP_UINT64;
		filter.weight.uint64 = &weight;
		filter.action.type = FWP_ACTION_BLOCK;
		filter.displayData.name = L"Test1";
		ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
		if (ret)
		{
			Debug("FwpmFilterAdd0 for IPv4 Failed: 0x%X\n", ret);
		}
		else
		{
			Debug("FwpmFilterAdd0 for IPv4 Ok.\n");
		}
		// Create the Filter (IPv4)
		Zero(&filter, sizeof(filter));
		filter.flags = 0;
		filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
		filter.weight.type = FWP_UINT64;
		filter.weight.uint64 = &weight;
		filter.action.type = FWP_ACTION_PERMIT;
		filter.displayData.name = L"Test1";
		ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
		if (ret)
		{
			Debug("FwpmFilterAdd0 for IPv4 Failed: 0x%X\n", ret);
		}
		else
		{
			Debug("FwpmFilterAdd0 for IPv4 Ok.\n");
		}
	}
}

bool TfSetFirewall(TF_SERVICE *svc, BUF *rules_text, UINT *num_rules_applied)
{
	static UINT dummy = 0;
	if (num_rules_applied == NULL) num_rules_applied = &dummy;
	*num_rules_applied = 0;

	if (svc == NULL)
	{
		return false;
	}

	if (MsIsAdmin() == false)
	{
		return false;
	}

	if (rules_text == NULL)
	{
		if (du_wfp_api != NULL)
		{
			if (svc->WfpEngine != NULL)
			{
				du_wfp_api->FwpmEngineClose0(svc->WfpEngine);
				svc->WfpEngine = NULL;
			}
		}
	}
	else
	{
		if (DuInitWfpApi() == false)
		{
			return false;
		}

		if (svc->WfpEngine != NULL)
		{
			du_wfp_api->FwpmEngineClose0(svc->WfpEngine);
			svc->WfpEngine = NULL;
		}

		FWPM_SESSION0 session = CLEAN;
		session.flags = FWPM_SESSION_FLAG_DYNAMIC;

		HANDLE hEngine = NULL;
		
		UINT ret = du_wfp_api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
		if (ret)
		{
			return false;
		}

		char provider_name[MAX_PATH] = CLEAN;
		char sublayer_name[MAX_PATH] = CLEAN;

		Format(provider_name, sizeof(provider_name), "ThinFwEngine Provider for %s", svc->StartupSettings.AppTitle);
		Format(sublayer_name, sizeof(sublayer_name), "ThinFwEngine Sublayer for %s", svc->StartupSettings.AppTitle);

		GUID provider = CLEAN;
		if (DuWfpCreateProvider(hEngine, &provider, provider_name) == false)
		{
			du_wfp_api->FwpmEngineClose0(hEngine);
			return false;
		}

		GUID sublayer = CLEAN;
		if (DuWfpCreateSublayer(hEngine, &sublayer, &provider, sublayer_name, 0xFFFF) == false)
		{
			du_wfp_api->FwpmEngineClose0(hEngine);
			return false;
		}

		BUF *text_copy = CloneBuf(rules_text);

		*num_rules_applied = FwApplyAllRulesFromLinesBuf(hEngine, &provider, &sublayer, text_copy);

		FreeBuf(text_copy);

		svc->WfpEngine = hEngine;
	}

	return true;
}

void DuWfpTest3()
{
}

void DuWfpTest2()
{
	UINT index = 0;
	FWPM_SESSION0 session = CLEAN;
	UINT ret;
	HANDLE hEngine;

	DuInitWfpApi();

	// Open the WFP (Dynamic Session)
	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	ret = du_wfp_api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
	if (ret)
	{
		Debug("FwpmEngineOpen0 Failed.\n");
		return;
	}

	GUID provider = CLEAN;
	if (DuWfpCreateProvider(hEngine, &provider, "dnp1") == false)
	{
		return;
	}

	GUID sublayer = CLEAN;
	if (DuWfpCreateSublayer(hEngine, &sublayer, &provider, "dns1", 0xFFFF) == false)
	{
		return;
	}

	BUF *text = ReadDump("@fwtest.txt");

	if (text == NULL)
	{
		Print("Text read error\n");
	}
	else
	{
		FwApplyAllRulesFromLinesBuf(hEngine, &provider, &sublayer, text);

		FreeBuf(text);
	}

	SleepThread(200);

	SOCK *s = Connect("x1.x2.aaaaa1.servers.ddns.sehosts.com", 80);
	Print("sock = %u\n", (UINT)(UINT64)s);
	ReleaseSock(s);

	//SOCK *s = Listen(8181);

	//if (s == NULL)
	//{
	//	WHERE;
	//}
	//else
	//{
	//	while (true)
	//	{
	//		SOCK *news = Accept(s);
	//		WHERE;

	//		while (true)
	//		{
	//			CHAR x = 'a';
	//			Send(news, &x, 1, false);
	//			SleepThread(100);
	//		}
	//	}
	//}
	
	Print("Quit>");
	GetLine(NULL, 0);
	
	du_wfp_api->FwpmEngineClose0(hEngine);
}

void DuWfpTest2_Old()
{
	UINT index = 0;

	FWPM_SESSION0 session;
	UINT ret;
	HANDLE hEngine;
	UINT64 FilterIPv4Id = 0;

	DuInitWfpApi();

	// Open the WFP (Dynamic Session)
	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	ret = du_wfp_api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
	if (ret)
	{
		Debug("FwpmEngineOpen0 Failed.\n");
		return;
	}

	{
		bool ipv6 = false;
		UINT port = 443;
		UINT protocol = IPPROTO_TCP;
		bool is_in = false;
		bool permit = true;

		FWPM_FILTER0 filter;
		UINT64 weight = ((UINT64)~((UINT64)0)) - (UINT64)index;
		wchar_t name[256];
		UINT ret;
		FWPM_FILTER_CONDITION0 c[16] = CLEAN;
		bool isv4 = !ipv6;

		UniFormat(name, sizeof(name), L"DU_Test1_%u", index++);

		UINT cond_index = 0;

		c[cond_index].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		c[cond_index].matchType = FWP_MATCH_EQUAL;
		c[cond_index].conditionValue.type = FWP_UINT16;
		c[cond_index].conditionValue.uint16 = port;
		cond_index++;

		c[cond_index].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		c[cond_index].matchType = FWP_MATCH_EQUAL;
		c[cond_index].conditionValue.type = FWP_UINT8;
		c[cond_index].conditionValue.uint8 = protocol;
		cond_index++;

		//c[cond_index].fieldKey = FWPM_CONDITION_FLAGS;
		//c[cond_index].matchType = FWP_MATCH_EQUAL;
		//c[cond_index].conditionValue.type = FWP_UINT8;
		//c[cond_index].conditionValue.uint8 = protocol;
		//cond_index++;

		Zero(&filter, sizeof(filter));
		filter.flags = 0;
		if (is_in)
		{
			filter.layerKey = isv4 ? FWPM_LAYER_INBOUND_TRANSPORT_V4 : FWPM_LAYER_INBOUND_TRANSPORT_V6;
		}
		else
		{
			filter.layerKey = isv4 ? FWPM_LAYER_OUTBOUND_TRANSPORT_V4 : FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
		}
		filter.weight.type = FWP_UINT64;
		filter.weight.uint64 = &weight;
		filter.action.type = permit ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
		filter.displayData.name = name;

		filter.filterCondition = c;
		filter.numFilterConditions = cond_index;

		ret = du_wfp_api->FwpmFilterAdd0(hEngine, &filter, NULL, NULL);
		if (ret)
		{
			Debug("DuWfpAddPortAcl: FwpmFilterAdd0 Failed: 0x%X\n", ret);
		}
	}


	{
		IP ip;
		IP mask;
		// Deny all IPv4
		ZeroIP4(&ip);
		ZeroIP4(&mask);
		DuWfpAddIpAcl(hEngine, false, &ip, &mask, ++index, false);
	}

}

// Start applying White List Rules
void *DuStartApplyWhiteListRules()
{
	FWPM_SESSION0 session;
	UINT ret;
	HANDLE hEngine = NULL;
	UINT index = 0;

	if (DuInitWfpApi() == false)
	{
		return NULL;
	}

	// Open the WFP (Dynamic Session)
	Zero(&session, sizeof(session));
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	ret = du_wfp_api->FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &hEngine);
	if (ret)
	{
		Debug("FwpmEngineOpen0 Failed.\n");
		return NULL;
	}

	if (true)
	{
		BUF *body = ReadDump(DU_WHITELIST_FILENAME);
		if (body != NULL)
		{
			while (true)
			{
				char *line = CfgReadNextLine(body);
				if (line == NULL)
				{
					break;
				}

				Trim(line);

				if (StartWith(line, "#") == false && StartWith(line, "//") == false &&
					StartWith(line, ";") == false)
				{
					TOKEN_LIST *t = ParseTokenWithoutNullStr(line, " \t");

					if (t != NULL)
					{
						if (t->NumTokens == 2)
						{
							char *type = t->Token[0];
							char *value = t->Token[1];

							if (StrCmpi(type, "IP") == 0)
							{
								IP ip;
								IP mask;

								if (ParseIpAndSubnetMask46(value, &ip, &mask))
								{
									DuWfpAddIpAcl(hEngine, true, &ip, &mask, ++index, true);
									DuWfpAddIpAcl(hEngine, false, &ip, &mask, ++index, true);
								}
							}
							else if (StrCmpi(type, "UDP") == 0)
							{
								UINT port = ToInt(value);
								if (port >= 1 && port <= 65535)
								{
									DuWfpAddPortAcl(hEngine, true, false, IP_PROTO_UDP, port, ++index, true);
									DuWfpAddPortAcl(hEngine, false, false, IP_PROTO_UDP, port, ++index, true);
								}
							}
						}

						FreeToken(t);
					}
				}

				Free(line);
			}

			FreeBuf(body);
		}
	}

	if (true)
	{
		IP ip, mask;

		// Deny all IPv4
		ZeroIP4(&ip);
		ZeroIP4(&mask);
		DuWfpAddIpAcl(hEngine, true, &ip, &mask, ++index, false);
		DuWfpAddIpAcl(hEngine, false, &ip, &mask, ++index, false);

		// Deny all IPv6
		ZeroIP6(&ip);
		ZeroIP6(&mask);
		DuWfpAddIpAcl(hEngine, true, &ip, &mask, ++index, false);
		DuWfpAddIpAcl(hEngine, false, &ip, &mask, ++index, false);
	}

	return hEngine;
}

// Stop applying White List Rules
void DuStopApplyWhiteListRules(void *handle)
{
	if (du_wfp_api	== NULL || handle == NULL)
	{
		return;
	}

	du_wfp_api->FwpmEngineClose0((HANDLE)handle);
}

void FwParseIpAndMask(IP *ip, IP *mask, char *str)
{
	if (ip == NULL || mask == NULL)
	{
		return;
	}

	bool error = false;

	ZeroIP4(ip);
	ZeroIP4(mask);

	if (StartWith(str, "any6") || StartWith(str, "all6"))
	{
		ZeroIP6(ip);
		ZeroIP6(mask);
		return;
	}
	else if (StartWith(str, "any") || StartWith(str, "all") || StrCmpi(str, "*") == 0)
	{
		ZeroIP4(ip);
		ZeroIP4(mask);
		return;
	}

	if (IsFilledStr(str))
	{
		if (InStr(str, "/") == false && StrToIP(ip, str))
		{
			if (IsIP6(ip))
			{
				IntToSubnetMask6(mask, 128);
			}
			else
			{
				IntToSubnetMask4(mask, 32);
			}
		}
		else
		{
			if (ParseIpAndMask46(str, ip, mask) == false)
			{
				error = true;
			}
		}
	}

	if (error)
	{
		if (IsIP6(ip))
		{
			StrToIP6(ip, "2001:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF");
			IntToSubnetMask6(mask, 128);
		}
		else
		{
			SetIP(ip, 1, 1, 1, 255);
			IntToSubnetMask4(mask, 32);
		}
	}
}

void FwParsePortRange(UINT *start, UINT *end, char *str)
{
	if (start == NULL || end == NULL)
	{
		return;
	}

	UINT p1 = 1, p2 = 65535;

	if (IsFilledStr(str))
	{
		TOKEN_LIST *t = ParseToken(str, "-:");

		if (t != NULL)
		{
			if (t->NumTokens >= 2 && IsNum(t->Token[0]) && IsNum(t->Token[1]))
			{
				p1 = ToInt(t->Token[0]);
				p2 = ToInt(t->Token[1]);
			}
			else if (t->NumTokens == 1 && IsNum(t->Token[0]))
			{
				p1 = p2 = ToInt(t->Token[0]);
			}
			else
			{
				p1 = 1;
				p2 = 65535;
			}

			FreeToken(t);
		}
	}

	p1 = MAX(p1, 1);
	p1 = MIN(p1, 65535);

	p2 = MAX(p2, 1);
	p2 = MIN(p2, 65535);

	if (p1 > p2)
	{
		UINT x = p1;
		p1 = p2;
		p2 = x;
	}

	*start = p1;
	*end = p2;
}

bool FwParseRuleStr(ACCESS *a, char *str)
{
	bool ret = false;
	if (a == NULL || str == NULL)
	{
		return false;
	}

	Zero(a, sizeof(ACCESS));

	char *line = CopyStr(str);

	Trim(line);

	if (StartWith(line, "#") == false && StartWith(line, "//") == false &&
		StartWith(line, ";") == false)
	{
		UINT comment_index = SearchStr(line, "#", 0);
		if (comment_index != INFINITE)
		{
			line[comment_index] = 0;
		}

		TOKEN_LIST *t = ParseTokenWithoutNullStr(line, " \t");

		if (t != NULL)
		{
			char *first = "";
			if (t->NumTokens >= 1)
			{
				first = t->Token[0];
			}

			if (IsFilledStr(first))
			{
				char *trust_server_tag = "trusted_server";
				char *trust_client_tag = "trusted_client";

				if (StartWith(line, trust_server_tag))
				{
					char tmp[MAX_SIZE] = CLEAN;
					StrCpy(tmp, sizeof(tmp), line + StrLen(trust_server_tag));
					Trim(tmp);

					wchar_t *fullpath = CopyUtfToUni(tmp);

					UINT atmark = UniSearchStrEx(fullpath, L"@", 0, true);

					if (atmark != INFINITE)
					{
						fullpath[atmark] = 0;
					}

					UniTrim(fullpath);

					UniTrimDoubleQuotation(fullpath);

					UniTrim(fullpath);

					a->Discard = false;
					UniStrCpy(a->Note, sizeof(a->Note), fullpath);

					a->UniqueId = FW_PARSED_ACCESS_UNIQUE_ID_EXEPATH;

					a->Jitter = FW_PARSED_ACCESS_JITTER_ALLOW_SERVER;

					Free(fullpath);

					ret = true;
				}
				else if (StartWith(line, trust_client_tag))
				{
					char tmp[MAX_SIZE] = CLEAN;
					StrCpy(tmp, sizeof(tmp), line + StrLen(trust_client_tag));
					Trim(tmp);

					wchar_t *fullpath = CopyUtfToUni(tmp);

					UINT atmark = UniSearchStrEx(fullpath, L"@", 0, true);

					if (atmark != INFINITE)
					{
						fullpath[atmark] = 0;
					}

					UniTrim(fullpath);

					UniTrimDoubleQuotation(fullpath);

					UniTrim(fullpath);

					a->Discard = false;
					UniStrCpy(a->Note, sizeof(a->Note), fullpath);

					a->UniqueId = FW_PARSED_ACCESS_UNIQUE_ID_EXEPATH;

					a->Jitter = FW_PARSED_ACCESS_JITTER_ALLOW_CLIENT;

					Free(fullpath);

					ret = true;
				}
				else
				{
					UINT proto = StrToProtocol(first);
					if (proto == 0 && StrCmpi(first, "ICMP"))
					{
						proto = IP_PROTO_ICMPV4;
					}

					if (proto == IP_PROTO_TCP || proto == IP_PROTO_UDP || IP_PROTO_ICMPV4 || IP_PROTO_ICMPV6)
					{
						if (t->NumTokens >= 5)
						{
							char *dir = t->Token[1];
							char *type = t->Token[2];
							char *action = t->Token[3];
							char *remoteip = t->Token[4];

							char *remoteport = t->NumTokens >= 6 ? t->Token[5] : "*";
							char *localport = t->NumTokens >= 7 ? t->Token[6] : "*";

							bool is_in = StartWith(dir, "i");
							bool is_new = StartWith(type, "n");
							bool is_permit = StartWith(action, "p") || StartWith(action, "a") || ToBool(action);

							IP ip = CLEAN;
							IP mask = CLEAN;

							FwParseIpAndMask(&ip, &mask, remoteip);

							UINT remoteport_start = 0, remoteport_end = 0;
							UINT localport_start = 0, localport_end = 0;

							FwParsePortRange(&remoteport_start, &remoteport_end, remoteport);
							FwParsePortRange(&localport_start, &localport_end, localport);

							a->CheckTcpState = true;
							a->Established = !is_new;
							a->Active = is_in;
							a->Discard = !is_permit;

							if (IsIP4(&ip))
							{
								a->DestIpAddress = IPToUINT(&ip);
								a->DestSubnetMask = IPToUINT(&mask);
							}
							else
							{
								a->IsIPv6 = true;
								Copy(&a->DestIpAddress6, ip.ipv6_addr, 16);
								Copy(&a->DestSubnetMask6, mask.ipv6_addr, 16);
							}

							if (proto == IP_PROTO_ICMPV4 || proto == IP_PROTO_ICMPV6)
							{
								proto = a->IsIPv6 ? IP_PROTO_ICMPV6 : IP_PROTO_ICMPV4;
							}

							a->Protocol = proto;

							a->SrcPortStart = localport_start;
							a->SrcPortEnd = localport_end;

							a->DestPortStart = remoteport_start;
							a->DestPortEnd = remoteport_end;

							UINT i;
							char tmpstr[MAX_SIZE] = CLEAN;
							for (i = 0;i < t->NumTokens;i++)
							{
								StrCat(tmpstr, sizeof(tmpstr), t->Token[i]);
								StrCat(tmpstr, sizeof(tmpstr), " ");
							}
							Trim(tmpstr);
							StrLower(tmpstr);

							StrToUni(a->Note, sizeof(a->Note), tmpstr);

							ret = true;
						}
					}
				}
			}

			FreeToken(t);
		}
	}

	Free(line);

	return ret;
}

UINT FwApplyAllRulesFromLinesBuf(HANDLE hEngine, GUID *provider, GUID *sublayer, BUF *buf)
{
	UINT index = 0;

	if (provider == NULL || sublayer == NULL || buf == NULL)
	{
		return 0;
	}

	UINT num_rules_applied = 0;

	// Add this exe as trusted
	wchar_t *this_exe_path = MsGetExeFileNameW();

	DuFwpAddTrustedExe(hEngine, provider, sublayer, ++index, this_exe_path, FW_PARSED_ACCESS_JITTER_ALLOW_SERVER | FW_PARSED_ACCESS_JITTER_ALLOW_CLIENT, false);

	SeekBufToBegin(buf);

	while (true)
	{
		char *line = CfgReadNextLine(buf);
		if (line == NULL)
		{
			break;
		}

		if (StrCmpi(line, "exit") == 0 || StrCmpi(line, "eof") == 0)
		{
			Free(line);
			break;
		}

		ACCESS a = CLEAN;

		if (FwParseRuleStr(&a, line))
		{
			if (a.UniqueId == FW_PARSED_ACCESS_UNIQUE_ID_EXEPATH)
			{
				// fw_trusted_exe
				DuFwpAddTrustedExe(hEngine, provider, sublayer, ++index, a.Note, a.Jitter, true);
			}
			else
			{
				// Normal ACL
				DuFwpAddAccess(hEngine, provider, sublayer, ++index, &a);
			}

			num_rules_applied++;
		}

		Free(line);
	}

	return num_rules_applied;
}

void TfReportThreadProc(THREAD *thread, void *param)
{
	wchar_t computer_name[128] = CLEAN;
	wchar_t computer_name_short[128] = CLEAN;
	TF_SERVICE *svc;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	svc = (TF_SERVICE *)param;

	SLOG *syslog = NULL;

	MsGetComputerNameFullEx(computer_name, sizeof(computer_name), false);

	UniStrCpy(computer_name_short, sizeof(computer_name_short), computer_name);
	UINT len = UniStrLen(computer_name_short);
	UINT i;
	for (i = 0;i < len;i++)
	{
		if (computer_name_short[i] == '.')
		{
			computer_name_short[i] = 0;
		}
	}

	BUF *current_mail_body = NewBuf();
	UINT current_mail_element_index = 0;
	UINT64 last_mail_sent_tick = 0;
	UINT64 mail_sleep_until_tick = 0;
	UINT64 mail_first_eventid = 0;
	UINT64 mail_last_eventid = 0;

	wchar_t prefix_tmp[MAX_PATH] = CLEAN;

	LIST *ms_fullpath_cache = MsNewConvertDosDevicePathToFullPathCache();

	LIST *mail_category_list = NewKvList();

	UINT64 last_update_tick = 0;

	while (true)
	{
		TF_REPORT_SETTINGS st = CLEAN;
		Lock(svc->CurrentReportSettingsLock);
		{
			Copy(&st, &svc->CurrentReportSettings, sizeof(TF_REPORT_SETTINGS));
		}
		Unlock(svc->CurrentReportSettingsLock);

		UINT64 now = Tick64();

		if (IsFilledStr(st.ReportMailHost) && st.ReportMailPort != 0 &&
			IsFilledStr(st.ReportMailFrom) && IsFilledStr(st.ReportMailTo))
		{
		}
		else
		{
			last_mail_sent_tick = now;
		}

		if (GetBufSize(current_mail_body) == 0)
		{
			last_mail_sent_tick = now;
		}

		if (mail_sleep_until_tick <= now &&
			GetBufSize(current_mail_body) >= 1 && 
			(
				(GetBufSize(current_mail_body) >= st.ReportMailMaxSize) ||
				(st.ReportMailIntervalMsec == 0 || now >= (last_mail_sent_tick + st.ReportMailIntervalMsec)) ||
				svc->ReportThreadHaltFlag
			)
		)
		{
			last_mail_sent_tick = now;

			char tmp[260];
			char date_str[64] = CLEAN;
			char time_str[64] = CLEAN;
			char mac_str[48] = CLEAN;
			IP my_ip = CLEAN;

			GetLastLocalIp(&my_ip, false);

			if (IsZero(svc->MacAddress, 6) == false)
			{
				BinToStr(mac_str, sizeof(mac_str), svc->MacAddress, 6);
			}

			UCHAR unique_id[16];
			Rand(unique_id, sizeof(unique_id));
			char unique_id_str[40] = CLEAN;
			BinToStr(unique_id_str, sizeof(unique_id_str), unique_id, sizeof(unique_id));

			UINT64 time = LocalTime64();
			GetDateStr64(date_str, sizeof(date_str), time);
			GetTimeStrMilli64(time_str, sizeof(time_str), time);

			UINT64 system_time = LocalToSystem64(time);

			char timezone_str[16] = CLEAN;
			MsGetTimezoneSuffixStr(timezone_str, sizeof(timezone_str));

			Format(tmp, sizeof(tmp), "\n---\nReported by %s\nMail timestamp: %s %s%s\n", svc->StartupSettings.AppTitle, date_str, time_str, timezone_str);
			WriteBuf(current_mail_body, tmp, StrLen(tmp));

			Format(tmp, sizeof(tmp), "Computer MAC address: %s\n", mac_str);
			WriteBuf(current_mail_body, tmp, StrLen(tmp));
			Format(tmp, sizeof(tmp), "Computer IP address: %r\n", &my_ip);
			WriteBuf(current_mail_body, tmp, StrLen(tmp));

			Format(tmp, sizeof(tmp), "Windows computer name: %S\n", computer_name);
			WriteBuf(current_mail_body, tmp, StrLen(tmp));

			if (st.ReportAppendUserName)
			{
				Format(tmp, sizeof(tmp), "Windows user name: %S\n", svc->Username);
				WriteBuf(current_mail_body, tmp, StrLen(tmp));
			}

			Format(tmp, sizeof(tmp), "Message Unique ID: %s\n", unique_id_str);
			WriteBuf(current_mail_body, tmp, StrLen(tmp));

			{
				// Get current MAC address
				UINT64 disk_free = 0;
				UINT64 disk_used = 0;
				UINT64 disk_total = 0;
				char disk_free_str[64] = CLEAN;
				char disk_used_str[64] = CLEAN;
				char disk_total_str[64] = CLEAN;
				char process_mem_usage_str[64] = CLEAN;

				PROCESS_MEMORY_COUNTERS meminfo = CLEAN;
				meminfo.cb = sizeof(meminfo);
				GetProcessMemoryInfo(GetCurrentProcess(), &meminfo, sizeof(meminfo));
				ToStr3(process_mem_usage_str, sizeof(process_mem_usage_str), meminfo.PagefileUsage);

				Win32GetDiskFree(MsGetWindowsDir(), &disk_free, &disk_used, &disk_total);
				ToStr3(disk_free_str, sizeof(disk_free_str), disk_free);
				ToStr3(disk_used_str, sizeof(disk_used_str), disk_used);
				ToStr3(disk_total_str, sizeof(disk_total_str), disk_total);

				char ssl_lib_ver[MAX_PATH] = CLEAN;

				char timezone_str[16] = CLEAN;
				MsGetTimezoneSuffixStr(timezone_str, sizeof(timezone_str));

				char system_boot_datetime[128] = CLEAN;
				GetDateTimeStr64(system_boot_datetime, sizeof(system_boot_datetime), SystemToLocal64(MsGetWindowsBootSystemTime()));

				char system_boot_span[128] = CLEAN;
				GetSpanStrMilli(system_boot_span, sizeof(system_boot_span), MsGetTickCount64());

				char svc_boot_datetime[128] = CLEAN;
				GetDateTimeStr64(svc_boot_datetime, sizeof(svc_boot_datetime), svc->BootLocalTime);

				char svc_boot_span[128] = CLEAN;
				GetSpanStrMilli(svc_boot_span, sizeof(svc_boot_span), Tick64() - svc->BootTick);

				GetSslLibVersion(ssl_lib_ver, sizeof(ssl_lib_ver));
				OS_INFO *os = GetOsInfo();
				MEMINFO mem = CLEAN;
				GetMemInfo(&mem);
				wchar_t computer_name[128] = CLEAN;
				MsGetComputerNameFullEx(computer_name, sizeof(computer_name), true);

				wchar_t tmp2[2048];
				UniFormat(tmp2, sizeof(tmp2),
					L"THINFW_BOOT_DATETIME: %S%S, THINFW_BOOT_UPTIME: %S\n"
					L"OsSystemName: %S, OsProductName: %S\nOsVendorName: %S, "
					L"OsVersion: %S\n"
					L"ProcessUserName: %s\n"
					L"SystemDiskFree: %S bytes, SystemDiskUsed: %S bytes, SystemDiskTotal: %S bytes\n"
					L"TotalVirtualMemory: %S bytes, UsedVirtualMemory: %S bytes, FreeVirtualMemory: %S bytes, \nTotalPhysMemory: %S bytes, UsedPhysMemory:%S bytes, FreePhysMemory:%S bytes, \nThinFwProcessAppPath: %s\nThinFwProcessMemoryUsage: %S bytes\n"
					L"OsBootDateTime: %S%S, OsUptime: %S\n"
					L"CEDAR_VER: %u, "
					L"CEDAR_BUILD: %u, BUILD_DATE: %04u/%02u/%02u %02u:%02u:%02u\n"
					L"THINLIB_COMMIT_ID: %S, THINLIB_VER_LABEL: %S\n\n"
					,
					svc_boot_datetime, timezone_str, svc_boot_span,
					os->OsSystemName, os->OsProductName, os->OsVendorName,
					os->OsVersion,
					MsGetUserNameExW(),
					disk_free_str, disk_used_str, disk_total_str,
					mem.TotalMemory_Str, mem.UsedMemory_Str, mem.FreeMemory_Str,
					mem.TotalPhys_Str, mem.UsedPhys_Str, mem.FreePhys_Str,
					MsGetExeFileNameW(),
					process_mem_usage_str,
					system_boot_datetime, timezone_str, system_boot_span,
					CEDAR_VER,
					CEDAR_BUILD, BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D,
					BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE,
					THINLIB_COMMIT_ID, THINLIB_VER_LABEL
				);

				char *utf = CopyUniToUtf(tmp2);

				WriteBuf(current_mail_body, utf, StrLen(utf));

				Free(utf);
			}

			WriteBufChar(current_mail_body, 0);

			if (IsFilledStr(st.ReportMailHost) && st.ReportMailPort != 0 &&
				IsFilledStr(st.ReportMailFrom) && IsFilledStr(st.ReportMailTo))
			{
				UINT64 mail_id = 0;

				wchar_t mail_id_w[64] = CLEAN;

				Lock(svc->EventIdEtcLock);
				{
					svc->LastMailId++;
					mail_id = svc->LastMailId;
				}
				Unlock(svc->EventIdEtcLock);

				UniFormat(mail_id_w, sizeof(mail_id_w), L"%I64u", mail_id);

				wchar_t mac_str_w[48] = CLEAN;
				StrToUni(mac_str_w, sizeof(mac_str_w), mac_str);

				StrToUni(prefix_tmp, sizeof(prefix_tmp), st.ReportMailSubjectPrefix);
				UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
					L"$hostname", computer_name_short, false);
				UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
					L"$macaddress", mac_str_w, false);
				UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
					L"$username", svc->Username, false);
				UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
					L"$mailid", mail_id_w, false);

				Sort(mail_category_list);

				char tmp[MAX_PATH];
				Format(tmp, sizeof(tmp), " - %u Events (", current_mail_element_index);
				UniStrCatA(prefix_tmp, sizeof(prefix_tmp), tmp);

				UINT i;
				for (i = 0;i < LIST_NUM(mail_category_list);i++)
				{
					KV_LIST *kv = LIST_DATA(mail_category_list, i);
					UINT *value = (UINT *)kv->Data;

					Format(tmp, sizeof(tmp), "%s: %u", kv->Key, *value);
					UniStrCatA(prefix_tmp, sizeof(prefix_tmp), tmp);

					if (i != (LIST_NUM(mail_category_list) - 1))
					{
						UniStrCatA(prefix_tmp, sizeof(prefix_tmp), ", ");
					}
				}

				UniStrCatA(prefix_tmp, sizeof(prefix_tmp), ")");

				char range[128] = CLEAN;
				if (mail_first_eventid != mail_last_eventid)
				{
					Format(range, sizeof(range), " (#%I64u-#%I64u)", mail_first_eventid, mail_last_eventid);
				}
				else
				{
					Format(range, sizeof(range), " (#%I64u)", mail_first_eventid);
				}

				UniStrCatA(prefix_tmp, sizeof(prefix_tmp), range);

				if (st.ReportAppendUserName)
				{
					wchar_t tmp3[128] = CLEAN;
					UniFormat(tmp3, sizeof(tmp3), L" (User: %s)", svc->Username);
					UniStrCat(prefix_tmp, sizeof(prefix_tmp), tmp3);
				}

				TOKEN_LIST *to_list = ParseToken(st.ReportMailTo, "/, \t");
					
				for (i = 0;i < to_list->NumTokens;i++)
				{
					char *to_address = to_list->Token[i];

					char *mail_body = SmtpGenerateUtf8MailBody(prefix_tmp, st.ReportMailFrom, to_address,
						system_time, current_mail_body->Buf);

					BUF *mail_error = NewBuf();

					TfLog(svc, "Sending mail to %S with the SMTP Server %S:%u  (items = %u, mail size = %u bytes)",
						to_address, st.ReportMailHost, st.ReportMailPort, current_mail_element_index, GetBufSize(current_mail_body));

					if (SmtpSendMailEx(st.ReportMailHost, st.ReportMailPort, st.ReportMailFrom, to_address,
						mail_body, mail_error, st.ReportMailUsername, st.ReportMailPassword, 0,
						st.ReportMailSslType, st.ReportMailAuthType) == false)
					{
						SeekBufToEnd(mail_error);
						WriteBufChar(mail_error, 0);

						TfLog(svc, "SMTP mail send error to %S. Giving up sending email within %u seconds. (SMTP server returned the error string: %S)",
							to_address,
							st.ReportMailFailSleepIntervalMsec / 1000,
							mail_error->Buf);

						mail_sleep_until_tick = Tick64() + (UINT64)st.ReportMailFailSleepIntervalMsec;
					}
					else
					{
						TfLog(svc, "SMTP mail is sent to %S (items = %u, body size = %u bytes)",
							to_address, current_mail_element_index, GetBufSize(current_mail_body));
					}

					FreeBuf(mail_error);

					Free(mail_body);
				}

				FreeToken(to_list);

				FreeKvList(mail_category_list);
				mail_category_list = NewKvList();
			}

			ClearBufEx(current_mail_body, true);
			current_mail_element_index = 0;
		}

		if (svc->ReportThreadHaltFlag)
		{
			// break after sending the final mail
			break;
		}

		if (st.EnableConfigAutoUpdate && st.ConfigAutoUpdateIntervalMsec != 0 &&
			IsFilledStr(st.ConfigAutoUpdateUrl) && (last_update_tick == 0 || now >= (last_update_tick + st.ConfigAutoUpdateIntervalMsec)))
		{
			last_update_tick = now;

			char url[1024] = CLEAN;

			wchar_t computer_name_w[128] = CLEAN;

			StrCpy(url, sizeof(url), st.ConfigAutoUpdateUrl);

			MsGetComputerNameFullEx(computer_name_w, sizeof(computer_name_w), false);

			char hostname[128] = CLEAN;

			UniToStr(hostname, sizeof(hostname), computer_name_w);

			ReplaceStr(url, sizeof(url), url, "$hostname", hostname);

			UCHAR mac[6] = CLEAN;
			TfGetCurrentMacAddress(mac);

			char mac_str[36] = CLEAN;
			BinToStr(mac_str, sizeof(mac_str), mac, 6);

			ReplaceStr(url, sizeof(url), url, "$macaddress", mac_str);

			char build_str[12] = CLEAN;
			ToStr(build_str, CEDAR_BUILD);

			char mode_str[12] = CLEAN;
			ToStr(mode_str, svc->StartupSettings.Mode);

			ReplaceStr(url, sizeof(url), url, "$build", build_str);

			ReplaceStr(url, sizeof(url), url, "$mode", mode_str);

			ReplaceStr(url, sizeof(url), url, "$app", svc->StartupSettings.AppTitle);

			ReplaceStr(url, sizeof(url), url, " ", "_");

			BUF *sha1_hash = StrToBin(st.ConfigAutoUpdateServerCertSha1);

			UCHAR *sha1_hash_ptr = NULL;
			UINT sha1_hash_count = 0;
			if (sha1_hash != NULL && sha1_hash->Size == SHA1_SIZE)
			{
				sha1_hash_ptr = sha1_hash->Buf;
				sha1_hash_count = 1;
			}

			BUF *http_error = NewBuf();
			UINT err_code = 0;

			BUF *downloaded_buf = HttpDownloadEx(url, st.ConfigAutoUpdateAuthUsername, st.ConfigAutoUpdateAuthPassword,
				NULL, 0, 0, &err_code, false, sha1_hash_ptr, sha1_hash_count, &svc->HaltFlag, 40 * 1024 * 1024,
				http_error, NULL, 0, NULL, 0);
			char *eof_tag = "[END_OF_FILE]";

			if (downloaded_buf != NULL)
			{
				if (SearchBin(downloaded_buf->Buf, 0, downloaded_buf->Size, eof_tag, StrLen(eof_tag)) != INFINITE)
				{
					wchar_t real_filename[MAX_PATH] = CLEAN;
					InnerFilePathW(real_filename, sizeof(real_filename), svc->StartupSettings.SettingFileName);

					BUF *current_buf = ReadDumpW(real_filename);

					if (current_buf == NULL || CmpBuf(current_buf, downloaded_buf) != 0)
					{
						LIST *current_ini = ReadIni(current_buf);

						if (current_buf == NULL || (IniBoolValue(current_ini, "EnableConfigAutoUpdate") && StrCmp(IniStrValue(current_ini, "ConfigAutoUpdateUrl"), st.ConfigAutoUpdateUrl) == 0))
						{
							UINT64 free_size = 0;
							if (Win32GetDiskFreeW(real_filename, &free_size, NULL, NULL))
							{
								if (free_size < 100000000)
								{
									TfLog(svc, "ConfigAutoUpdate: Update failed. The free disk space (%I64u bytes) is less than 100MB.", free_size);
								}
								else
								{
									//UniStrCat(real_filename, sizeof(real_filename), L".test.txt");

									if (DumpBufSafeW(downloaded_buf, real_filename) == false)
									{
										TfLog(svc, "ConfigAutoUpdate: Update filed. Cannot write to localdisk file '%s'.", real_filename);
									}
									else
									{
										TfLog(svc, "ConfigAutoUpdate: The localdisk file '%s' is updated from the URL '%S'. Old size = %u bytes, New size = %u bytes.", real_filename, url,
											current_buf->Size, downloaded_buf->Size);

										svc->ConfigUpdatedReloadFlag = true;
										Set(svc->HaltEvent);
									}
								}
							}
						}

						FreeIni(current_ini);
					}

					FreeBuf(current_buf);
				}
				else
				{
					TfLog(svc, "ConfigAutoUpdate: The downloaded file contents from the URL '%S' has no '%S' tag in the body. The contents is ignored.",
						url, eof_tag);
				}

				FreeBuf(downloaded_buf);
			}
			else
			{
				SeekBufToEnd(http_error);
				WriteBufChar(http_error, 0);
				TfLog(svc, "ConfigAutoUpdate: HTTP download error from the URL '%S'. Error code = %u, Error string = '%s'. Error detail: '%S'",
					url, err_code, _E(err_code), http_error->Buf);
			}

			FreeBuf(sha1_hash);
			FreeBuf(http_error);
		}

		DIFF_ENTRY *e = NULL;
		
		LockQueue(svc->ReportQueue);
		{
			e = GetNext(svc->ReportQueue);
		}
		UnlockQueue(svc->ReportQueue);

		if (e == NULL)
		{
			Wait(svc->ReportThreadHaltEvent, 256);
			continue;
		}

		UINT gethostname_flag = GETHOSTNAME_FLAG_NO_NETBIOS_NAME | GETHOSTNAME_USE_DNS_API;

		if (st.EnableTcpHostnameLookup)
		{
			// Resolve hostname
			if (e->Param == MS_THINFW_ENTRY_TYPE_TCP)
			{
				MS_THINFW_ENTRY_TCP *tcp = (MS_THINFW_ENTRY_TCP *)&e->Data;

				if (IsEmptyStr(tcp->RemoteIPHostname_Resolved))
				{
					if (IsZeroIP(&tcp->Tcp.RemoteIP) == false && IsLocalHostIP(&tcp->Tcp.RemoteIP) == false)
					{
						GetHostNameEx(tcp->RemoteIPHostname_Resolved, sizeof(tcp->RemoteIPHostname_Resolved), &tcp->Tcp.RemoteIP, st.HostnameLookupTimeoutMsec, gethostname_flag);
					}
				}
			}
			else if (e->Param == MS_THINFW_ENTRY_TYPE_RDP)
			{
				MS_THINFW_ENTRY_RDP *rdp = (MS_THINFW_ENTRY_RDP *)&e->Data;

				if (IsEmptyStr(rdp->ClientHostname_Resolved))
				{
					if (IsZeroIP(&rdp->ClientIp) == false && IsLocalHostIP(&rdp->ClientIp) == false)
					{
						GetHostNameEx(rdp->ClientHostname_Resolved, sizeof(rdp->ClientHostname_Resolved), &rdp->ClientIp, st.HostnameLookupTimeoutMsec, gethostname_flag);
					}
				}
			}
			else if (e->Param == MS_THINFW_ENTRY_TYPE_BLOCK)
			{
				MS_THINFW_ENTRY_BLOCK *block = (MS_THINFW_ENTRY_BLOCK *)&e->Data;

				if (IsEmptyStr(block->RemoteIPHostname_Resolved))
				{
					if (IsZeroIP(&block->RemoteIP) == false && IsLocalHostIP(&block->RemoteIP) == false)
					{
						GetHostNameEx(block->RemoteIPHostname_Resolved, sizeof(block->RemoteIPHostname_Resolved), &block->RemoteIP, st.HostnameLookupTimeoutMsec, gethostname_flag);
					}
				}
			}
			else if (e->Param == MS_THINFW_ENTRY_TYPE_FILESHARE_SESSION)
			{
				MS_THINFW_ENTRY_FILESHARE_SESSION *sess = (MS_THINFW_ENTRY_FILESHARE_SESSION *)&e->Data;
				if (IsEmptyStr(sess->ClientHostname_Resolved))
				{
					char ipstr[128] = CLEAN;
					if (UniStartWith(sess->ClientComputerName, L"\\\\"))
					{
						UniToStr(ipstr, sizeof(ipstr), sess->ClientComputerName + 2);
					}
					else
					{
						UniToStr(ipstr, sizeof(ipstr), sess->ClientComputerName);
					}

					Trim(ipstr);

					if (StrLen(ipstr) >= 1)
					{
						IP ip = CLEAN;
						if (StrToIP(&ip, ipstr))
						{
							if (IsZeroIP(&ip) == false && IsLocalHostIP(&ip) == false)
							{
								GetHostNameEx(sess->ClientHostname_Resolved, sizeof(sess->ClientHostname_Resolved), &ip, st.HostnameLookupTimeoutMsec, gethostname_flag);
							}
						}
					}
				}
			}
		}

		if (e->Param == MS_THINFW_ENTRY_TYPE_BLOCK)
		{
			MS_THINFW_ENTRY_BLOCK *block = (MS_THINFW_ENTRY_BLOCK *)&e->Data;

			wchar_t exe_fullpath[512] = CLEAN;

			if (MsConvertDosDevicePathToFullPathWithCache(ms_fullpath_cache, exe_fullpath, sizeof(exe_fullpath), block->ProcessExeName))
			{
				UniStrCpy(block->ProcessExeName, sizeof(block->ProcessExeName), exe_fullpath);
			}
		}

		bool ok = true;

		if (st.ReportSendEngineEvent == false && e->Param == MS_THINFW_ENTRY_TYPE_STREVENT)
		{
			ok = false;
		}

		char category[64] = CLEAN;
		wchar_t tmp[THINFW_MAX_LINE_SIZE] = CLEAN;
		wchar_t tmp2[THINFW_MAX_LINE_SIZE] = CLEAN;
		UINT64 systemtime_value = 0;

		if (ok)
		{
			TfGetStr(category, sizeof(category), tmp, sizeof(tmp), e, &systemtime_value);
		}

		if (UniIsFilledUniStr(tmp))
		{
			UINT64 event_id = 0;

			wchar_t event_id_w[64] = CLEAN;

			Lock(svc->EventIdEtcLock);
			{
				svc->LastEventId++;
				event_id = svc->LastEventId;
			}
			Unlock(svc->EventIdEtcLock);

			UniFormat(event_id_w, sizeof(event_id_w), L"%I64u", event_id);

			if (st.ReportAppendUniqueId)
			{
				UCHAR rand[20] = CLEAN;
				Rand(rand, sizeof(rand));
				char rand_str[64] = CLEAN;
				BinToStr(rand_str, sizeof(rand_str), rand, sizeof(rand));
				UniFormat(tmp2, sizeof(tmp2), L" (UniqueId: %S)", rand_str);
				UniStrCat(tmp, sizeof(tmp), tmp2);
			}

			char mac_str[48] = CLEAN;
			wchar_t mac_str_w[48] = CLEAN;
			char date_str[64] = CLEAN;
			char time_str[64] = CLEAN;

			char timezone_str[16] = CLEAN;

			BinToStr(mac_str, sizeof(mac_str), svc->MacAddress, 6);
			StrToUni(mac_str_w, sizeof(mac_str_w), mac_str);

			UINT64 time;
			
			if (systemtime_value != 0)
			{
				time = SystemToLocal64(systemtime_value);
			}
			else
			{
				time = SystemToLocal64(TickToTime(e->Tick));
			}

			GetDateStr64(date_str, sizeof(date_str), time);
			GetTimeStrMilli64(time_str, sizeof(time_str), time);

			if (st.ReportAppendTimeZone)
			{
				char timezone_str[16] = CLEAN;
				MsGetTimezoneSuffixStr(timezone_str, sizeof(timezone_str));
			}

			if (st.ReportSaveToDir)
			{
				bool ok = true;

				if (e->Param == MS_THINFW_ENTRY_TYPE_FILESHARE_FILE && st.ReportSaveToDirNoFileShareAccessLog)
				{
					ok = false;
				}

				if (ok)
				{
					TfLogEx(svc, category, "(%S %S%S) %s", date_str, time_str, timezone_str, tmp);
				}
			}

			if (st.ReportSyslogOnlyWhenLocked == false || (e->Flags & MS_THINFW_ENTRY_FLAG_LOCKED))
			{
				bool ok = true;

				if (e->Param == MS_THINFW_ENTRY_TYPE_FILESHARE_FILE && st.ReportSyslogNoFileShareAccessLog)
				{
					ok = false;
				}

				if (ok && IsFilledStr(st.ReportSyslogHost) && st.ReportSyslogPort != 0)
				{
					if (syslog == NULL)
					{
						syslog = NewSysLog(NULL, 0);
					}

					SetSysLog(syslog, st.ReportSyslogHost, st.ReportSyslogPort);

					StrToUni(prefix_tmp, sizeof(prefix_tmp), st.ReportSyslogPrefix);
					UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
						L"$hostname", computer_name, false);
					UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
						L"$macaddress", mac_str_w, false);
					wchar_t username_tmp[MAX_PATH] = CLEAN;
					UniStrCpy(username_tmp, sizeof(username_tmp), svc->Username);
					UniReplaceStrEx(username_tmp, sizeof(username_tmp), username_tmp, L" ", L"_", true);
					UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
						L"$username", username_tmp, false);
					UniReplaceStrEx(prefix_tmp, sizeof(prefix_tmp), prefix_tmp,
						L"$eventid", event_id_w, false);

					UniFormat(tmp2, sizeof(tmp2), L"%S %S%S %s [%S] %s",
						date_str, time_str, timezone_str, prefix_tmp, category, tmp);

					SendSysLog(syslog, tmp2);

				}
			}

			if (st.ReportMailOnlyWhenLocked == false || (e->Flags & MS_THINFW_ENTRY_FLAG_LOCKED))
			{
				if (IsFilledStr(st.ReportMailHost) && st.ReportMailPort != 0 &&
					IsFilledStr(st.ReportMailFrom) && IsFilledStr(st.ReportMailTo))
				{
					ClearUniStr(tmp2, sizeof(tmp2));

					if (current_mail_element_index == 0)
					{
						mail_first_eventid = event_id;
					}

					mail_last_eventid = event_id;

					current_mail_element_index++;

					UniFormat(tmp2, sizeof(tmp2),
						L"Event #%I64u: %S %S%S\n[%S] %s\n\n",
						event_id,
						date_str, time_str, timezone_str,
						category, tmp);

					char *utf8 = CopyUniToUtf(tmp2);
					WriteBuf(current_mail_body, utf8, StrLen(utf8));
					Free(utf8);

					UINT zero = 0;
					KV_LIST *kv = AddOrGetKvList(mail_category_list, category, &zero, sizeof(UINT), 0, 0);
					if (kv != NULL)
					{
						(*((UINT *)kv->Data))++;
					}
				}
			}
		}

		Free(e);

	}

	if (syslog != NULL)
	{
		FreeSysLog(syslog);
	}

	FreeBuf(current_mail_body);

	FreeKvList(mail_category_list);

	MsFreeConvertDosDevicePathToFullPathCache(ms_fullpath_cache);
}

bool TfGetCurrentMacAddress(UCHAR *mac)
{
	bool ret = false;
	Zero(mac, 6);
	if (mac == NULL)
	{
		return false;
	}

	IP target = CLEAN;
	SetIP(&target, 8, 8, 8, 8);

	MS_ADAPTER_LIST *nic_list = MsCreateAdapterList();

	UINT i;

	if (nic_list != NULL)
	{
		ROUTE_ENTRY *rt = GetBestRouteEntry(&target);
		if (rt != NULL)
		{
			// Get MAC address from the routing table
			for (i = 0;i < nic_list->Num;i++)
			{
				MS_ADAPTER *a = nic_list->Adapters[i];

				switch (a->Status)
				{
				case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
				case MIB_IF_OPER_STATUS_UNREACHABLE:
				case MIB_IF_OPER_STATUS_DISCONNECTED:
					break;

				default:
					DoNothing();
					UINT j;
					for (j = 0;j < a->NumGateway;j++)
					{
						if (CmpIpAddr(&a->Gateways[j], &rt->GatewayIP) == 0)
						{
							if (a->AddressSize == 6 && IsZero(a->Address, 6) == false)
							{
								Copy(mac, a->Address, 6);

								ret = true;
							}
							break;
						}
					}
					break;
				}

				if (ret)
				{
					break;
				}
			}

			Free(rt);
		}

		// Get MAC address (inchiki #1)
		if (ret == false)
		{
			for (i = 0;i < nic_list->Num;i++)
			{
				MS_ADAPTER *a = nic_list->Adapters[i];

				switch (a->Status)
				{
				case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
				case MIB_IF_OPER_STATUS_UNREACHABLE:
				case MIB_IF_OPER_STATUS_DISCONNECTED:
				case MIB_IF_OPER_STATUS_CONNECTING:
					break;

				default:
					DoNothing();
					UINT j;
					for (j = 0;j < a->NumGateway;j++)
					{
						if (IsZeroIp(&a->IpAddresses[0]) == false &&
							IsZeroIP(&a->Gateways[0]) == false &&
							(a->RecvBytes != 0 || a->SendBytes != 0)
							)
						{
							if (a->AddressSize == 6 && IsZero(a->Address, 6) == false)
							{
								Copy(mac, a->Address, 6);

								ret = true;
							}
							break;
						}
					}
					break;
				}

				if (ret)
				{
					break;
				}
			}
		}

		// Get MAC address (inchiki #2)
		if (ret == false)
		{
			for (i = 0;i < nic_list->Num;i++)
			{
				MS_ADAPTER *a = nic_list->Adapters[i];

				switch (a->Status)
				{
				case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
				case MIB_IF_OPER_STATUS_UNREACHABLE:
				case MIB_IF_OPER_STATUS_DISCONNECTED:
				case MIB_IF_OPER_STATUS_CONNECTING:
					break;

				default:
					DoNothing();
					UINT j;
					for (j = 0;j < a->NumGateway;j++)
					{
						if (IsZeroIp(&a->IpAddresses[0]) == false &&
							(a->RecvBytes != 0 || a->SendBytes != 0)
							)
						{
							if (a->AddressSize == 6 && IsZero(a->Address, 6) == false)
							{
								Copy(mac, a->Address, 6);

								ret = true;
							}
							break;
						}
					}
					break;
				}

				if (ret)
				{
					break;
				}
			}
		}

		// Get MAC address (inchiki #3)
		if (ret == false)
		{
			for (i = 0;i < nic_list->Num;i++)
			{
				MS_ADAPTER *a = nic_list->Adapters[i];

				switch (a->Status)
				{
				case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
				case MIB_IF_OPER_STATUS_UNREACHABLE:
				case MIB_IF_OPER_STATUS_DISCONNECTED:
				case MIB_IF_OPER_STATUS_CONNECTING:
					break;

				default:
					DoNothing();
					UINT j;
					for (j = 0;j < a->NumGateway;j++)
					{
						if (a->AddressSize == 6 && IsZero(a->Address, 6) == false)
						{
							Copy(mac, a->Address, 6);

							ret = true;
						}
						break;
					}
					break;
				}

				if (ret)
				{
					break;
				}
			}
		}

		// Get MAC address (inchiki #4)
		if (ret == false)
		{
			for (i = 0;i < nic_list->Num;i++)
			{
				MS_ADAPTER *a = nic_list->Adapters[i];

				UINT j;
				for (j = 0;j < a->NumGateway;j++)
				{
					if (a->AddressSize == 6 && IsZero(a->Address, 6) == false)
					{
						Copy(mac, a->Address, 6);

						ret = true;
					}
					break;
				}

				if (ret)
				{
					break;
				}
			}
		}
	}

	MsFreeAdapterList(nic_list);

	return ret;
}

void TfGetStr(char *category, UINT category_size, wchar_t *dst, UINT dst_size, DIFF_ENTRY *e, UINT64 *ret_systemtime)
{
	static UINT64 _dummy = 0;
	ClearUniStr(dst, 0);
	ClearStr(category, category_size);
	if (dst == NULL || e == NULL || category == NULL)
	{
		return;
	}
	if (ret_systemtime == NULL)
	{
		ret_systemtime = &_dummy;
	}

	wchar_t ep_info[768] = CLEAN;
	char ep_hostname[270] = CLEAN;
	wchar_t proc_info[MAX_SIZE * 2] = CLEAN;
	wchar_t tmpw[MAX_SIZE] = CLEAN;
	wchar_t rdp_session_info[MAX_SIZE] = CLEAN;
	char local_ip[128] = CLEAN;
	char remote_ip[128] = CLEAN;

	switch (e->Param)
	{
	case MS_THINFW_ENTRY_TYPE_STREVENT:
		StrCpy(category, category_size, "ENGINE_LOG");
		MS_THINFW_ENTRY_STREVENT *event = (MS_THINFW_ENTRY_STREVENT *)&e->Data;
		UniStrCpy(dst, dst_size, event->Str);
		break;

	case MS_THINFW_ENTRY_TYPE_DNS:
		StrCpy(category, category_size, "DNS");
		MS_THINFW_ENTRY_DNS *dns = (MS_THINFW_ENTRY_DNS *)&e->Data;
		UniFormat(dst, dst_size, L"(Type: %S, Name: %S, Data: %S)",
			dns->Type, dns->Name, dns->Data);
		break;

	case MS_THINFW_ENTRY_TYPE_WINEVENT:
		StrCpy(category, category_size, "WIN_EVENTLOG");
		MS_EVENTITEM *winevent = (MS_EVENTITEM *)&e->Data;
		*ret_systemtime = winevent->SystemTime64;
		wchar_t user[256] = CLEAN;

		if (UniIsFilledStr(winevent->Username) || UniIsFilledStr(winevent->DomainName))
		{
			UniFormat(user, sizeof(user), L"%s\\%s", winevent->DomainName, winevent->Username);
		}

		UniFormat(dst, dst_size, L"EVENT_ID=%u;Src=%s;Index=%I64u;Msg=%s;User=%s;EventLogName=%s;",
			winevent->EventId, winevent->ProviderName, winevent->Index,
			winevent->Message, user, winevent->EventLogName);
		break;

	case MS_THINFW_ENTRY_TYPE_BLOCK:
		DoNothing();

		MS_THINFW_ENTRY_BLOCK *block = (MS_THINFW_ENTRY_BLOCK *)&e->Data;

		if (block->Protocol == IP_PROTO_TCP)
		{
			if (block->IsReceive)
			{
				StrCpy(category, category_size, "TCP_BLOCK_SERVER");
			}
			else
			{
				StrCpy(category, category_size, "TCP_BLOCK_CLIENT");
			}
		}
		else if (block->Protocol == IP_PROTO_UDP)
		{
			if (block->IsReceive)
			{
				StrCpy(category, category_size, "UDP_BLOCK_SERVER");
			}
			else
			{
				StrCpy(category, category_size, "UDP_BLOCK_CLIENT");
			}
		}

		IPToStr(local_ip, sizeof(local_ip), &block->LocalIP);
		IPToStr(remote_ip, sizeof(remote_ip), &block->RemoteIP);

		if (IsFilledStr(block->RemoteIPHostname_Resolved))
		{
			Format(ep_hostname, sizeof(ep_hostname), "RemoteHost: %s, ",
				block->RemoteIPHostname_Resolved);
		}

		if (IsZeroIP(&block->RemoteIP))
		{
			UniFormat(ep_info, sizeof(ep_info),
				L"(LocalIP: %S, LocalPort: %u)",
				local_ip, block->LocalPort);
		}
		else
		{
			UniFormat(ep_info, sizeof(ep_info),
				L"(%SRemoteIP: %S, RemotePort: %u, LocalIP: %S, LocalPort: %u)",
				ep_hostname,
				remote_ip, block->RemotePort,
				local_ip, block->LocalPort);
		}

		ClearStr(ep_hostname, 0);

		UniFormat(proc_info, sizeof(proc_info),
			L" ProcessInfo=(AppPath: %s, User: %s\\%s)",
			UniIsFilledStr(block->ProcessExeName) ? block->ProcessExeName : L"(unknown)",
			block->DomainName,
			block->Username);

		UniStrCat(dst, dst_size, ep_info);
		UniStrCat(dst, dst_size, proc_info);
		break;

	case MS_THINFW_ENTRY_TYPE_PROCESS:
		DoNothing();
		MS_THINFW_ENTRY_PROCESS *proc = (MS_THINFW_ENTRY_PROCESS *)&e->Data;

		if (UniIsFilledStr(proc->CommandLineW))
		{
			UniFormat(tmpw, sizeof(tmpw), L", FullCommandLine: %s", proc->CommandLineW);
		}

		if (UniIsFilledStr(proc->Rdp.WinStationName))
		{
			char rdp_client_info[MAX_PATH] = CLEAN;

			if (IsZeroIP(&proc->Rdp.ClientIp) == false)
			{
				if (IsFilledStr(proc->Rdp.ClientHostname_Resolved))
				{
					Format(ep_hostname, sizeof(ep_hostname), "RdpClientHost: %s, ",
						proc->Rdp.ClientHostname_Resolved);
				}

				Format(rdp_client_info, sizeof(rdp_client_info), ", %sRdpClientIP: %r, RdpClientLocalIP: %r",
					ep_hostname,
					&proc->Rdp.ClientIp, &proc->Rdp.ClientLocalIp);
			}

			UniFormat(rdp_session_info, sizeof(rdp_session_info),
				L" SessionInfo=(User: %s\\%s, SessionName: %s%S)",
				proc->Domain,
				proc->Username,
				proc->Rdp.WinStationName,
				rdp_client_info);
		}

		Format(category, category_size, "PROCESS_%s", e->IsAdded ? "START" : "STOP");

		wchar_t svc_info[1024] = CLEAN;

		if (UniIsFilledStr(proc->Svc.ServiceName))
		{
			UniFormat(svc_info, sizeof(svc_info), L" ServiceInfo=(ServiceName: %s, DisplayName: %s, ServiceType: %S, ServicePath: %s)",
				proc->Svc.ServiceName, proc->Svc.ServiceTitle, proc->Svc.ServiceType, proc->Svc.ExeFilenameW);
		}

		UniFormat(dst, dst_size, L"(PID: %u, %ubit, AppPath: %s, User: %s\\%s, SessionId: %u%s)%s%s",
			proc->ProcessId,
			proc->Is64BitProcess ? 64 : 32,
			proc->ExeFilenameW,
			proc->Domain,
			proc->Username,
			proc->SessionId,
			tmpw,
			svc_info,
			rdp_session_info);

		break;

	case MS_THINFW_ENTRY_TYPE_SERVICE:
		DoNothing();
		MS_THINFW_ENTRY_SERVICE *svc = (MS_THINFW_ENTRY_SERVICE *)&e->Data;

		Format(category, category_size, "SERVICE_%s", svc->ServiceState);
		StrUpper(category);

		UniFormat(dst, dst_size, L"(ServiceName: %s, DisplayName: %s, ServiceType: %S, ServicePath: %s, ProcessId: %u, State: %S)",
			svc->ServiceName, svc->ServiceTitle, svc->ServiceType, svc->ExeFilenameW, svc->ProcessId, svc->ServiceState);

		break;

	case MS_THINFW_ENTRY_TYPE_FILESHARE_SESSION:
		StrCpy(category, category_size, e->IsAdded ? "FILESHARE_CONNECTED" : "FILESHARE_DISCONNECTED");
		MS_THINFW_ENTRY_FILESHARE_SESSION *sess = (MS_THINFW_ENTRY_FILESHARE_SESSION *)&e->Data;

		if (IsFilledStr(sess->ClientHostname_Resolved))
		{
			Format(ep_hostname, sizeof(ep_hostname), "ClientHostname: %s, ",
				sess->ClientHostname_Resolved);
		}

		UniFormat(dst, dst_size, L"(%SClientComputer: %s, ClientUserName: %s)",
			ep_hostname, sess->ClientComputerName, sess->ClientUserName);
		break;

	case MS_THINFW_ENTRY_TYPE_FILESHARE_FILE:
		StrCpy(category, category_size, "FILESHARE_ACCESS");
		MS_THINFW_ENTRY_FILESHARE_FILE *access = (MS_THINFW_ENTRY_FILESHARE_FILE *)&e->Data;

		UniFormat(dst, dst_size, L"(AccessId: %u, AccessUserName: %s, AccessFileName: %s, AccessMode: %S)",
			access->Id, access->UserName, access->FileName, access->Mode);
		break;

	case MS_THINFW_ENTRY_TYPE_RDP:
		StrCpy(category, category_size,  e->IsAdded ? "RDP_START" : "RDP_STOP");
		MS_THINFW_ENTRY_RDP *rdp = (MS_THINFW_ENTRY_RDP *)&e->Data;

		if (IsFilledStr(rdp->ClientHostname_Resolved))
		{
			Format(ep_hostname, sizeof(ep_hostname), "ClientHost: %s, ",
				rdp->ClientHostname_Resolved);
		}
		if (UniIsFilledStr(rdp->Username))
		{
			UniFormat(tmpw, sizeof(tmpw), L"%s\\%s", UniIsFilledStr(rdp->Domain) ? rdp->Domain : L".", rdp->Username);
		}
		else
		{
			UniStrCpy(tmpw, sizeof(tmpw), L"<login_screen>");
		}

		UniFormat(dst, dst_size, L"(SessionID: %u, SessionName: %s, State: %S, %SClientIP: %r, ClientLocalIP: %r, ClientBuild: %u, Username: %s)",
			rdp->SessionId, rdp->WinStationName, rdp->SessionState,
			ep_hostname, &rdp->ClientIp, &rdp->ClientLocalIp, rdp->ClientLocalBuild, tmpw);
		break;

	case MS_THINFW_ENTRY_TYPE_TCP:
		DoNothing();
		MS_THINFW_ENTRY_TCP *tcp = (MS_THINFW_ENTRY_TCP *)&e->Data;

		IPToStr(local_ip, sizeof(local_ip), &tcp->Tcp.LocalIP);
		IPToStr(remote_ip, sizeof(remote_ip), &tcp->Tcp.RemoteIP);

		if (tcp->Tcp.Status == TCP_STATE_LISTEN)
		{
			if (IsZeroIP(&tcp->Tcp.LocalIP))
			{
				if (IsIP4(&tcp->Tcp.LocalIP))
				{
					StrCpy(local_ip, sizeof(local_ip), "IPv4_Any");
				}
				else
				{
					StrCpy(local_ip, sizeof(local_ip), "IPv6_Any");
				}
			}
		}

		if (IsFilledStr(tcp->RemoteIPHostname_Resolved))
		{
			Format(ep_hostname, sizeof(ep_hostname), "RemoteHost: %s, ",
				tcp->RemoteIPHostname_Resolved);
		}

		if (IsZeroIP(&tcp->Tcp.RemoteIP))
		{
			UniFormat(ep_info, sizeof(ep_info),
				L"(LocalIP: %S, LocalPort: %u)",
				local_ip, tcp->Tcp.LocalPort);
		}
		else
		{
			UniFormat(ep_info, sizeof(ep_info),
				L"(%SRemoteIP: %S, RemotePort: %u, LocalIP: %S, LocalPort: %u)",
				ep_hostname,
				remote_ip, tcp->Tcp.RemotePort,
				local_ip, tcp->Tcp.LocalPort);
		}

		ClearStr(ep_hostname, 0);

		if (tcp->HasProcessInfo)
		{
			MS_THINFW_ENTRY_PROCESS *proc = &tcp->Process;

			if (UniIsFilledStr(proc->CommandLineW))
			{
				UniFormat(tmpw, sizeof(tmpw), L", FullCommandLine: %s", proc->CommandLineW);
			}

			if (UniIsFilledStr(proc->Rdp.WinStationName))
			{
				char rdp_client_info[MAX_PATH] = CLEAN;

				if (IsZeroIP(&proc->Rdp.ClientIp) == false)
				{
					if (IsFilledStr(proc->Rdp.ClientHostname_Resolved))
					{
						Format(ep_hostname, sizeof(ep_hostname), "RdpClientHost: %s, ",
							proc->Rdp.ClientHostname_Resolved);
					}

					Format(rdp_client_info, sizeof(rdp_client_info), ", %sRdpClientIP: %r, RdpClientLocalIP: %r",
						ep_hostname,
						&proc->Rdp.ClientIp, &proc->Rdp.ClientLocalIp);
				}

				UniFormat(rdp_session_info, sizeof(rdp_session_info),
					L" SessionInfo=(User: %s\\%s, SessionName: %s%S)",
					proc->Domain,
					proc->Username,
					proc->Rdp.WinStationName,
					rdp_client_info);

			}

			wchar_t svc_info[1024] = CLEAN;

			if (UniIsFilledStr(proc->Svc.ServiceName))
			{
				UniFormat(svc_info, sizeof(svc_info), L" ServiceInfo=(ServiceName: %s, DisplayName: %s)",
					proc->Svc.ServiceName, proc->Svc.ServiceTitle);
			}

			UniFormat(proc_info, sizeof(proc_info),
				L" ProcessInfo=(PID: %u, %ubit, AppPath: %s, User: %s\\%s, SessionId: %u%s)%s%s",
				tcp->Process.ProcessId,
				tcp->Process.Is64BitProcess ? 64 : 32,
				tcp->Process.ExeFilenameW,
				tcp->Process.Domain,
				tcp->Process.Username,
				tcp->Process.SessionId,
				tmpw,
				svc_info,
				rdp_session_info);
		}
		else
		{
			if (tcp->ProcessId != 4)
			{
				UniFormat(proc_info, sizeof(proc_info), L" ProcessInfo=(PID: %u, AppPath: System)", tcp->ProcessId);
			}
			else if (tcp->ProcessId != 0)
			{
				UniFormat(proc_info, sizeof(proc_info), L" ProcessInfo=(PID: %u, Unknown)", tcp->ProcessId);
			}
			else
			{
				UniFormat(proc_info, sizeof(proc_info), L" ProcessInfo=(Unknown)");
			}
		}

		StrCpy(category, category_size, tcp->Type);

		UniStrCat(dst, dst_size, ep_info);
		UniStrCat(dst, dst_size, proc_info);

		break;
	}
}

DIFF_ENTRY *TfNewStrEvent(char *str)
{
	DIFF_ENTRY *e;
	wchar_t *tmp = CopyStrToUni(str);

	e = TfNewStrEventW(tmp);

	Free(tmp);

	return e;
}

DIFF_ENTRY *TfNewStrEventW(wchar_t *str)
{
	MS_THINFW_ENTRY_STREVENT e = CLEAN;

	UniStrCpy(e.Str, sizeof(e.Str), str);

	return NewDiffEntry(L"", e.Str, sizeof(e), MS_THINFW_ENTRY_TYPE_STREVENT, Tick64());
}

void TfInsertStrEvent(TF_SERVICE *svc, wchar_t *str)
{
	if (svc == NULL || str == NULL)
	{
		return;
	}

	LockQueue(svc->ReportQueue);
	{
		InsertQueue(svc->ReportQueue, TfNewStrEventW(str));
	}
	UnlockQueue(svc->ReportQueue);
}

void TfUpdateReg(TF_SERVICE *svc, bool read)
{
	if (svc == NULL)
	{
		return;
	}

	wchar_t *exe = MsGetExeFileNameW();
	wchar_t exe2[MAX_PATH] = CLEAN;
	UniStrCpy(exe2, sizeof(exe2), exe);
	UniStrLower(exe2);
	UniTrim(exe2);

	UCHAR hash[SHA1_SIZE] = CLEAN;
	HashSha1(hash, exe2, UniStrSize(exe2));

	char instance_id[64] = CLEAN;

	BinToStr(instance_id, sizeof(instance_id), hash, 12);
	StrLower(instance_id);

	char reg_key_str[MAX_PATH] = CLEAN;

	Format(reg_key_str, sizeof(reg_key_str),
		"Software\\Thin Firewall System\\RunningInstances\\Instance_%s",
		instance_id);

	MsRegWriteStrW(REG_CURRENT_USER, reg_key_str, "ExePath", exe);
	MsRegWriteInt64Str(REG_CURRENT_USER, reg_key_str, "LastUpdate", SystemTime64());

	Lock(svc->EventIdEtcLock);
	{
		if (read)
		{
			svc->LastEventId = MsRegReadInt64Str(REG_CURRENT_USER, reg_key_str, "LastEventId");
			svc->LastMailId = MsRegReadInt64Str(REG_CURRENT_USER, reg_key_str, "LastMailId");
		}

		MsRegWriteInt64Str(REG_CURRENT_USER, reg_key_str, "LastEventId", svc->LastEventId);
		MsRegWriteInt64Str(REG_CURRENT_USER, reg_key_str, "LastMailId", svc->LastMailId);
	}
	Unlock(svc->EventIdEtcLock);
}

void TfMain(TF_SERVICE *svc)
{
	if (svc == NULL)
	{
		return;
	}

	char *single_instance_name = "dn_thinfw_single_instance";

	INSTANCE *current_single_instance = NULL;

	UINT64 last_cfg_read = 0;
	UINT64 last_poll = 0;
	UINT64 last_netinfo = 0;
	UINT64 last_eventlog_read = 0;
	UINT64 last_watch_dns_cache = 0;

	BUF *cfg_file_content = NewBuf();

	LIST *sid_cache = MsNewSidToUsernameCache();

	LIST *svc_data_cache_kv = NewKvListW();

	LIST *ini = ReadIni(cfg_file_content);

	INTERRUPT_MANAGER *im = NewInterruptManager();

	bool ever_enabled = false;

	bool cfg_Enable = false;
	UINT cfg_SettingReloadIntervalMsec = 15 * 1000;
	UINT cfg_WatchPollingIntervalMsec = 250;
	bool cfg_EnableWatchRdp = false;
	bool cfg_EnableWatchDns = false;
	bool cfg_EnableWatchWindowsEventLog = false;
	bool cfg_EnableWatchProcess = false;
	bool cfg_EnableWatchService = false;
	bool cfg_EnableWatchFileShare = false;
	bool cfg_EnableWatchTcp = false;
	bool cfg_EnableWatchFwBlock = false;
	bool cfg_WatchOnlyWhenLocked = false;
	bool cfg_IncludeProcessCommandLine = false;
	bool cfg_EnableFirewall = false;
	bool cfg_EnableFirewallOnlyWhenLocked = false;
	UINT cfg_GetNetworkInfoIntervalMsec = 300000;
	bool cfg_IgnoreDNSoverTCPSession = false;
	UINT cfg_ReportMaxQueueLength = 1024;
	UINT cfg_InputIdleTimerMsec = 15 * 60 * 1000;
	UINT cfg_WindowsEventLogPollIntervalMsec = 10 * 1000;
	bool cfg_EnableDailyAliveMessage = false;
	UINT cfg_SendDailyAliveNoticeHhmmss = 0;
	bool cfg_AlwaysWatchDnsCache = false;
	UINT cfg_WatchDnsCacheIntervalMsec = 15000;

	wchar_t cfg_WindowsEventLogNames[1024] = CLEAN;

	bool wfp_log_start_failed = false;

	UCHAR lastState_mac[6] = CLEAN;
	bool lastState_Enable = false;

	UINT lastState_locked = INFINITE;
	UINT lastState_watchActive = INFINITE;
	UINT lastState_firewall = INFINITE;

	LIST *current_list = NULL;

	LIST *current_dns_servers_list = MsGetCurrentDnsServersList();

	UINT current_process_id = MsGetCurrentProcessId();

	UINT config_revision = 0;

	DU_WFP_LOG_SETTINGS wfp_log_settings = CLEAN;

	DU_WFP_LOG *wfp_log = NULL;

	MS_EVENTREADER_SESSION *event_reader = MsNewEventReaderSession();

	UINT64 last_regupdate = 0;

	HASH_LIST *dns_hash = NULL;

	wchar_t tmp[2048];

	// Get MAC address
	UCHAR mac[6] = CLEAN;
	TfGetCurrentMacAddress(mac);
	Copy(svc->MacAddress, mac, 6);

	// Init report thread
	svc->ReportQueue = NewQueue();
	svc->ReportThreadHaltEvent = NewEvent();
	svc->ReportThread = NewThread(TfReportThreadProc, svc);

	TfUpdateReg(svc, true);

	bool another_instance_error_show_flag = false;

	UINT last_past_days_since_base = 0;

	char *eof_tag = "[END_OF_FILE]";

	svc->BootTick = Tick64();
	svc->BootLocalTime = LocalTime64();

	while (svc->HaltFlag == false)
	{
		UINT64 now = Tick64();

		if (last_cfg_read == 0 || now >= (last_cfg_read + (UINT64)cfg_SettingReloadIntervalMsec) || svc->ConfigUpdatedReloadFlag)
		{
			svc->ConfigUpdatedReloadFlag = false;

			// Config file reload
			BUF *new_content = ReadDumpW(svc->StartupSettings.SettingFileName);

			//if (new_content == NULL)
			//{
			//	// Install default config and retry
			//	TfInstallDefaultConfig(svc->StartupSettings.SettingFileName, false, true, NULL);

			//	new_content = ReadDumpW(svc->StartupSettings.SettingFileName);
			//}

			if (new_content != NULL && SearchBin(new_content->Buf, 0, new_content->Size, eof_tag, StrLen(eof_tag)) != INFINITE)
			{
				// Compare
				if (CmpBuf(new_content, cfg_file_content) != 0)
				{
					// Reload settings
					LIST *new_ini = ReadIni(new_content);

					if (IniBoolValue(new_ini, "Enable"))
					{
						if (current_single_instance == NULL)
						{
							current_single_instance = NewSingleInstanceEx(single_instance_name, false);

							if (current_single_instance == NULL)
							{
								if (another_instance_error_show_flag == false)
								{
									TfLog(svc, "Error: While 'Enable' is set to 'true' on the configuration file, another instance of Thin Firewall System has been already running on this computer. This Thin Firewall System instance will suspend until another instance will be stopped.");
									another_instance_error_show_flag = true;
								}

								FreeIni(new_ini);
								FreeBuf(new_content);

								goto L_BOOT_ERROR;
							}
							else
							{
								if (another_instance_error_show_flag)
								{
									TfLog(svc, "Information: Another Thin Firewall instance stopped. So this instance of Thin Firewall started.");
									another_instance_error_show_flag = false;
								}
							}
						}
					}

					another_instance_error_show_flag = false;

					config_revision++;

					if (config_revision >= 2)
					{
						UniFormat(tmp, sizeof(tmp), L"Config file reloaded. Revision: %u", config_revision);
						TfInsertStrEvent(svc, tmp);
					}

					FreeIni(ini);

					ini = new_ini;

					FreeBuf(cfg_file_content);
					cfg_file_content = new_content;

					// Interpret ini
					cfg_Enable = IniBoolValue(ini, "Enable");

					cfg_EnableDailyAliveMessage = IniBoolValue(ini, "EnableDailyAliveMessage");
					cfg_SendDailyAliveNoticeHhmmss = IniIntValue(ini, "SendDailyAliveNoticeHhmmss");

					cfg_EnableFirewall = IniBoolValue(ini, "EnableFirewall");
					cfg_EnableFirewallOnlyWhenLocked = IniBoolValue(ini, "EnableFirewallOnlyWhenLocked");
					cfg_SettingReloadIntervalMsec = IniIntValue(ini, "SettingReloadIntervalMsec");
					if (cfg_SettingReloadIntervalMsec == 0)
					{
						cfg_SettingReloadIntervalMsec = 5 * 1000;
					}
					cfg_SettingReloadIntervalMsec = MAX(cfg_SettingReloadIntervalMsec, 1000);
					cfg_SettingReloadIntervalMsec = MIN(cfg_SettingReloadIntervalMsec, 60 * 5 * 1000);
					cfg_WatchPollingIntervalMsec = IniIntValue(ini, "WatchPollingIntervalMsec");
					if (cfg_WatchPollingIntervalMsec == 0)
					{
						cfg_WatchPollingIntervalMsec = 250;
					}
					cfg_WatchPollingIntervalMsec = MAX(cfg_WatchPollingIntervalMsec, 100);
					cfg_EnableWatchRdp = IniBoolValue(ini, "EnableWatchRdp");
					cfg_EnableWatchDns = IniBoolValue(ini, "EnableWatchDns");
					cfg_EnableWatchProcess = IniBoolValue(ini, "EnableWatchProcess");
					cfg_EnableWatchService = IniBoolValue(ini, "EnableWatchService");
					cfg_IncludeProcessCommandLine = IniBoolValue(ini, "IncludeProcessCommandLine");
					cfg_WatchOnlyWhenLocked = IniBoolValue(ini, "WatchOnlyWhenLocked");
					cfg_EnableWatchTcp = IniBoolValue(ini, "EnableWatchTcp");
					cfg_EnableWatchFwBlock = IniBoolValue(ini, "EnableWatchFwBlock");

					cfg_GetNetworkInfoIntervalMsec = IniIntValue(ini, "GetNetworkInfoIntervalMsec");
					if (cfg_GetNetworkInfoIntervalMsec == 0)
					{
						cfg_GetNetworkInfoIntervalMsec = 300000;
					}
					cfg_GetNetworkInfoIntervalMsec = MAX(cfg_GetNetworkInfoIntervalMsec, 5 * 1000);

					cfg_ReportMaxQueueLength = IniIntValue(ini, "ReportMaxQueueLength");
					if (cfg_ReportMaxQueueLength == 0)
					{
						cfg_ReportMaxQueueLength = 1024;
					}

					cfg_EnableWatchFileShare = IniBoolValue(ini, "EnableWatchFileShare");

					cfg_AlwaysWatchDnsCache = IniBoolValue(ini, "AlwaysWatchDnsCache");

					cfg_WatchDnsCacheIntervalMsec = IniIntValue(ini, "WatchDnsCacheIntervalMsec");
					if (cfg_WatchDnsCacheIntervalMsec == 0)
					{
						cfg_WatchDnsCacheIntervalMsec = 15000;
					}
					cfg_WatchDnsCacheIntervalMsec = MAX(cfg_WatchDnsCacheIntervalMsec, 100);

					cfg_InputIdleTimerMsec = IniIntValue(ini, "InputIdleTimerMsec");
					if (cfg_InputIdleTimerMsec == 0)
					{
						cfg_InputIdleTimerMsec = 15 * 60 * 1000;
					}

					cfg_EnableWatchWindowsEventLog = IniBoolValue(ini, "EnableWatchWindowsEventLog");

					UniStrCpy(cfg_WindowsEventLogNames, sizeof(cfg_WindowsEventLogNames),
						IniUniStrValue(ini, "WindowsEventLogNames"));

					cfg_WindowsEventLogPollIntervalMsec = IniIntValue(ini, "WindowsEventLogPollIntervalMsec");
					if (cfg_WindowsEventLogPollIntervalMsec == 0)
					{
						cfg_WindowsEventLogPollIntervalMsec = 10 * 1000;
					}
					cfg_WindowsEventLogPollIntervalMsec = MAX(cfg_WindowsEventLogPollIntervalMsec, 1000);

					cfg_IgnoreDNSoverTCPSession = IniBoolValue(ini, "IgnoreDNSoverTCPSession");

					TF_REPORT_SETTINGS rep = CLEAN;
					rep.EnableTcpHostnameLookup = IniBoolValue(ini, "EnableTcpHostnameLookup");

					rep.ReportMailMaxSize = IniIntValue(ini, "ReportMailMaxSize");
					rep.ReportMailMaxSize = MIN(rep.ReportMailMaxSize, 5000000);

					rep.ReportMailFailSleepIntervalMsec = IniIntValue(ini, "ReportMailFailSleepIntervalMsec");
					rep.ReportMailFailSleepIntervalMsec = MAX(rep.ReportMailFailSleepIntervalMsec, 15000);

					rep.ReportMailOnlyWhenLocked = IniBoolValue(ini, "ReportMailOnlyWhenLocked");
					rep.ReportSendEngineEvent = IniBoolValue(ini, "ReportSendEngineEvent");
					rep.ReportMailIntervalMsec = IniIntValue(ini, "ReportMailIntervalMsec");
					StrCpy(rep.ReportMailHost, sizeof(rep.ReportMailHost), IniStrValue(ini, "ReportMailHost"));
					rep.ReportMailPort = IniIntValue(ini, "ReportMailPort");
					StrCpy(rep.ReportMailUsername, sizeof(rep.ReportMailUsername), IniStrValue(ini, "ReportMailUsername"));
					StrCpy(rep.ReportMailPassword, sizeof(rep.ReportMailPassword), IniStrValue(ini, "ReportMailPassword"));
					// Special tenuki by daiyuu nobori 2023/05/10 !!!
					if (StrCmpi(rep.ReportMailHost, "smtp01.example-smtp.thintele-oss.arpanet.jp") == 0 &&
						StrCmpi(rep.ReportMailUsername, "example") == 0 &&
						StrCmpi(rep.ReportMailPassword, "example") == 0)
					{
						// 見るな！！ by daiyuu nobori 2023/05/10
						char *tenuki_secret_str = "SampleConfig:Himitsu:SupamuNiZettaiTsukauna!!TsukawaretaraHaishiSuruzo!!OnegaiDesukaraSupamuNiTsukkawanaideKudasai!!Sushi_Kudasai!!By_Daiyuu_Nobori_2023/05/10";
						UCHAR sha1[SHA1_SIZE];
						HashSha1(sha1, tenuki_secret_str, StrLen(tenuki_secret_str));
						char tmp[MAX_PATH];
						BinToStr(tmp, sizeof(tmp), sha1, sizeof(sha1));
						StrLower(tmp);
						tmp[32] = 0;
						StrCpy(rep.ReportMailPassword, sizeof(rep.ReportMailPassword), tmp);
					}
					rep.ReportMailSslType = IniIntValue(ini, "ReportMailSslType");
					rep.ReportMailAuthType = IniIntValue(ini, "ReportMailAuthType");
					StrCpy(rep.ReportMailFrom, sizeof(rep.ReportMailFrom), IniStrValue(ini, "ReportMailFrom"));
					StrCpy(rep.ReportMailTo, sizeof(rep.ReportMailTo), IniStrValue(ini, "ReportMailTo"));
					StrCpy(rep.ReportMailSubjectPrefix, sizeof(rep.ReportMailSubjectPrefix), IniStrValue(ini, "ReportMailSubjectPrefix"));
					Trim(rep.ReportMailSubjectPrefix);

					rep.ReportSyslogOnlyWhenLocked = IniBoolValue(ini, "ReportSyslogOnlyWhenLocked");
					rep.ReportSyslogNoFileShareAccessLog = IniBoolValue(ini, "ReportSyslogNoFileShareAccessLog");
					StrCpy(rep.ReportSyslogHost, sizeof(rep.ReportSyslogHost), IniStrValue(ini, "ReportSyslogHost"));
					rep.ReportSyslogPort = IniIntValue(ini, "ReportSyslogPort");
					StrCpy(rep.ReportSyslogPrefix, sizeof(rep.ReportSyslogPrefix), IniStrValue(ini, "ReportSyslogPrefix"));
					Trim(rep.ReportSyslogPrefix);

					rep.ReportSaveToDir = IniBoolValue(ini, "ReportSaveToDir");
					rep.ReportSaveToDirNoFileShareAccessLog = IniBoolValue(ini, "ReportSaveToDirNoFileShareAccessLog");
					rep.ReportAppendUniqueId = IniBoolValue(ini, "ReportAppendUniqueId");
					rep.ReportAppendTimeZone = IniBoolValue(ini, "ReportAppendTimeZone");
					rep.ReportAppendUserName = IniBoolValue(ini, "ReportAppendUserName");

					rep.EnableConfigAutoUpdate = IniBoolValue(ini, "EnableConfigAutoUpdate");
					rep.ConfigAutoUpdateIntervalMsec = IniIntValue(ini, "ConfigAutoUpdateIntervalMsec");

					if (rep.ConfigAutoUpdateIntervalMsec == 0)
					{
						rep.ConfigAutoUpdateIntervalMsec = 3600 * 1000;
					}

					rep.ConfigAutoUpdateIntervalMsec = MAX(rep.ConfigAutoUpdateIntervalMsec, 5 * 1000);

					StrCpy(rep.ConfigAutoUpdateUrl, sizeof(rep.ConfigAutoUpdateUrl), IniStrValue(ini, "ConfigAutoUpdateUrl"));
					StrCpy(rep.ConfigAutoUpdateAuthUsername, sizeof(rep.ConfigAutoUpdateAuthUsername), IniStrValue(ini, "ConfigAutoUpdateAuthUsername"));
					StrCpy(rep.ConfigAutoUpdateAuthPassword, sizeof(rep.ConfigAutoUpdateAuthPassword), IniStrValue(ini, "ConfigAutoUpdateAuthPassword"));
					StrCpy(rep.ConfigAutoUpdateServerCertSha1, sizeof(rep.ConfigAutoUpdateServerCertSha1), IniStrValue(ini, "ConfigAutoUpdateServerCertSha1"));

					rep.HostnameLookupTimeoutMsec = IniIntValue(ini, "HostnameLookupTimeoutMsec");

					if (rep.HostnameLookupTimeoutMsec == 0) rep.HostnameLookupTimeoutMsec = 500;

					Lock(svc->CurrentReportSettingsLock);
					{
						Copy(&svc->CurrentReportSettings, &rep, sizeof(TF_REPORT_SETTINGS));
					}
					Unlock(svc->CurrentReportSettingsLock);
				}
				else
				{
					FreeBuf(new_content);
					new_content = NULL;
				}
			}
			else
			{
				FreeBuf(new_content);
				new_content = NULL;
L_BOOT_ERROR:
				cfg_Enable = false;
				cfg_SettingReloadIntervalMsec = 15 * 1000;
				cfg_WatchPollingIntervalMsec = 250;
				cfg_EnableWatchRdp = false;
				cfg_EnableWatchDns = false;
				cfg_EnableWatchProcess = false;
				cfg_EnableWatchService = false;
				cfg_EnableWatchTcp = false;
				cfg_EnableWatchFwBlock = false;
				cfg_WatchOnlyWhenLocked = false;
				cfg_IncludeProcessCommandLine = false;
				cfg_EnableFirewall = false;
				cfg_EnableFirewallOnlyWhenLocked = false;
				cfg_ReportMaxQueueLength = 1024;
				cfg_InputIdleTimerMsec = 15 * 60 * 1000;
				cfg_EnableWatchWindowsEventLog = false;
				cfg_WindowsEventLogPollIntervalMsec = 10 * 1000;
				cfg_EnableDailyAliveMessage = false;
				cfg_SendDailyAliveNoticeHhmmss = 0;
				cfg_AlwaysWatchDnsCache = false;
				cfg_EnableWatchFileShare = false;
				cfg_WatchDnsCacheIntervalMsec = 15000;
				ClearUniStr(cfg_WindowsEventLogNames, sizeof(cfg_WindowsEventLogNames));
				lastState_locked = INFINITE;
				lastState_watchActive = INFINITE;
				lastState_firewall = INFINITE;
			}

			last_cfg_read = now;
			AddInterrupt(im, now + (UINT64)cfg_SettingReloadIntervalMsec);
		}

		if (cfg_Enable)
		{
			ever_enabled = true;
		}

		if (cfg_Enable == false)
		{
			if (current_single_instance != NULL)
			{
				FreeSingleInstance(current_single_instance);
				current_single_instance = NULL;
			}
		}

		if (lastState_Enable != cfg_Enable)
		{
			TfUpdateReg(svc, cfg_Enable);

			lastState_Enable = cfg_Enable;

			if (cfg_Enable)
			{
				svc->BootTick = Tick64();
				svc->BootLocalTime = LocalTime64();

				TfRaiseAliveEvent(svc, true);
			}
			else
			{
				TfLog(svc, "-------------------- Stop %S --------------------", svc->StartupSettings.AppTitle);

				UniFormat(tmp, sizeof(tmp), L"%S is stopped.", svc->StartupSettings.AppTitle);
				TfInsertStrEvent(svc, tmp);
			}
		}

		if (cfg_Enable)
		{
			if (last_netinfo == 0 || now >= (last_netinfo + (UINT64)cfg_GetNetworkInfoIntervalMsec))
			{
				last_netinfo = now;
				AddInterrupt(im, now + (UINT64)cfg_GetNetworkInfoIntervalMsec);

				// Update current DNS servers list
				MsFreeDnsServersList(current_dns_servers_list);
				current_dns_servers_list = MsGetCurrentDnsServersList();

				// Get current MAC address
				UCHAR mac[6] = CLEAN;

				if (TfGetCurrentMacAddress(mac))
				{
					if (Cmp(mac, lastState_mac, 6) != 0)
					{
						Copy(lastState_mac, mac, 6);

						char mac_str[24] = CLEAN;
						BinToStr(mac_str, sizeof(mac_str), mac, 6);

						TfLog(svc, "This computer's MAC address: %S", mac_str);

						Copy(svc->MacAddress, mac, 6);
					}
				}
			}
		}

		if (cfg_Enable && cfg_EnableWatchWindowsEventLog)
		{
			if (last_eventlog_read == 0 || now >= (last_eventlog_read + (UINT64)cfg_WindowsEventLogPollIntervalMsec))
			{
				last_eventlog_read = now;
				AddInterrupt(im, now + (UINT64)cfg_WindowsEventLogPollIntervalMsec);

				if (svc->ReportQueue->num_item < cfg_ReportMaxQueueLength)
				{
					LIST *new_events = MsWatchEvents(event_reader, cfg_WindowsEventLogNames, 100);

					if (new_events != NULL && LIST_NUM(new_events) >= 1)
					{
						LockQueue(svc->ReportQueue);
						{
							UINT i;
							for (i = 0;i < LIST_NUM(new_events);i++)
							{
								MS_EVENTITEM *e = LIST_DATA(new_events, i);

								DIFF_ENTRY *entry = NewDiffEntry(L"", e, sizeof(MS_EVENTITEM), MS_THINFW_ENTRY_TYPE_WINEVENT, now);

								entry->Flags |= MS_THINFW_ENTRY_FLAG_LOCKED;

								InsertQueue(svc->ReportQueue, entry);
							}
						}
						UnlockQueue(svc->ReportQueue);
					}

					FreeListMemItemsAndReleaseList(new_events);
				}
			}
		}

		if (cfg_Enable && cfg_AlwaysWatchDnsCache)
		{
			if (last_watch_dns_cache == 0 || now >= (last_watch_dns_cache + (UINT64)cfg_WatchDnsCacheIntervalMsec))
			{
				last_watch_dns_cache = now;
				AddInterrupt(im, now + (UINT64)cfg_WatchDnsCacheIntervalMsec);

				if (dns_hash != NULL && dns_hash->NumItems > DU_WATCH_DNS_CACHE_MAX_ENTRIES)
				{
					MsFreeDnsHash(dns_hash);
					dns_hash = NULL;
				}

				if (dns_hash == NULL)
				{
					dns_hash = MsNewDnsHash();
				}

				MsMainteDnsHash(dns_hash, NULL);
			}
		}

		if (cfg_Enable == false)
		{
			if (dns_hash != NULL)
			{
				MsFreeDnsHash(dns_hash);
				dns_hash = NULL;
			}
		}

		if (ever_enabled && (last_poll == 0 || now >= (last_poll + (UINT64)cfg_WatchPollingIntervalMsec)))
		{
			last_poll = now;
			AddInterrupt(im, now + (UINT64)cfg_WatchPollingIntervalMsec);

			bool is_firewall_active = false;

			if (cfg_Enable)
			{
				// Determine whether run the watch procedures
				bool is_locked = false;
				bool is_watch_active = false;

				if (svc->StartupSettings.Mode == TF_SVC_MODE_SYSTEMMODE)
				{
					// Use the terminal service API
					is_locked = !MsWtsOneOrMoreUnlockedSessionExists(NULL);
				}
				else
				{
					// Use mouse pointer movement to detect inactivity
					if (MsWtsOneOrMoreUnlockedSessionExists(NULL) == false)
					{
						is_locked = true;
					}
					else if (MsIsScreenSaverRunning())
					{
						is_locked = true;
					}
					else
					{
						UINT64 idle_tick = MsGetIdleTick();
						if (idle_tick >= 1 && idle_tick >= (UINT64)cfg_InputIdleTimerMsec)
						{
							is_locked = true;
						}
					}
				}

				if (lastState_locked != is_locked)
				{
					lastState_locked = is_locked;

					TfLog(svc, "Desktop lock state is changed. New state is '%S'.",
						is_locked ? "Locked" : "Unlocked");
				}

				if (cfg_WatchOnlyWhenLocked)
				{
					is_watch_active = is_locked;
				}
				else
				{
					is_watch_active = true;
				}

				if (cfg_EnableFirewallOnlyWhenLocked)
				{
					is_firewall_active = cfg_EnableFirewall && is_locked;
				}
				else
				{
					is_firewall_active = cfg_EnableFirewall;
				}

				if (lastState_watchActive != is_watch_active)
				{
					lastState_watchActive = is_watch_active;

					TfLog(svc, "Watcher active state is changed. New state is '%S'.",
						is_watch_active ? "Active" : "Inactive");
				}

				bool is_watch_fw_block_active = false;
				if (is_watch_active && cfg_EnableWatchFwBlock)
				{
					is_watch_fw_block_active = true;
				}

				if (is_watch_fw_block_active == false)
				{
					wfp_log_start_failed = false;
				}

				if (is_watch_fw_block_active && wfp_log == NULL)
				{
					DU_WFP_LOG_SETTINGS wfp_log_settings = CLEAN;

					if (wfp_log_start_failed == false)
					{
						wfp_log = DuWfpStartLog2(&wfp_log_settings);

						if (wfp_log == NULL)
						{
							wfp_log_start_failed = true;
						}
					}
				}
				else if (is_watch_fw_block_active == false && wfp_log != NULL)
				{
					DuWfpStopLog2(wfp_log);
					wfp_log = NULL;
					wfp_log_start_failed = false;
				}

				if (is_watch_active)
				{
					UINT flags = 0;

					if (cfg_IncludeProcessCommandLine == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_PROC_NO_CMD_LINE;
					}

					if (cfg_EnableWatchTcp == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_NO_TCP;
					}

					if (cfg_EnableWatchRdp == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_NO_RDP;
					}

					if (cfg_EnableWatchDns == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_NO_DNS_CACHE;
					}

					if (cfg_EnableWatchProcess == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_NO_PROCESS;
					}

					if (cfg_EnableWatchService == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_NO_SERVICE;
					}

					if (cfg_EnableWatchFileShare == false)
					{
						flags |= MS_GET_THINFW_LIST_FLAGS_NO_FILESHARE;
					}

					flags |= MS_GET_THINFW_LIST_FLAGS_NO_LOCALHOST_RDP;

					LIST *wfp_log_list = NewDiffList();

					if (wfp_log != NULL)
					{
						UINT64 tick = Tick64();

						LockList(wfp_log->CurrentEntryList);
						{
							DuWfpLogGc(wfp_log, tick, true);

							UINT i;
							for (i = 0;i < LIST_NUM(wfp_log->CurrentEntryList);i++)
							{
								DIFF_ENTRY *e = LIST_DATA(wfp_log->CurrentEntryList, i);

								if (e->Param == MS_THINFW_ENTRY_TYPE_BLOCK &&
									e->DataSize == sizeof(MS_THINFW_ENTRY_BLOCK))
								{
									bool ok = true;

									MS_THINFW_ENTRY_BLOCK *b = (MS_THINFW_ENTRY_BLOCK *)e->Data;

									if (cfg_IgnoreDNSoverTCPSession &&
										b->Protocol == IP_PROTO_TCP &&
										b->IsReceive == false &&
										b->RemotePort == NAT_DNS_PROXY_PORT &&
										MsIsIpInDnsServerList(current_dns_servers_list, &b->RemoteIP))
									{
										// DNS over TCP: Do not report
										ok = false;
									}

									if (ok)
									{
										DIFF_ENTRY *e2 = CloneDiffEntry(e);

										//MS_THINFW_ENTRY_BLOCK *b1 = (MS_THINFW_ENTRY_BLOCK *)&e->Data;
										//MS_THINFW_ENTRY_BLOCK *b2 = (MS_THINFW_ENTRY_BLOCK *)&e2->Data;

										e2->IsAdded = e2->IsRemoved = false;

										Add(wfp_log_list, e2);
									}
								}
							}
						}
						UnlockList(wfp_log->CurrentEntryList);
					}

					if (dns_hash != NULL && dns_hash->NumItems > DU_WATCH_DNS_CACHE_MAX_ENTRIES)
					{
						MsFreeDnsHash(dns_hash);
						dns_hash = NULL;
					}

					if (dns_hash == NULL)
					{
						dns_hash = MsNewDnsHash();
					}

					UINT64 tick = Tick64();

					LIST *now_list = MsGetThinFwList(sid_cache, flags, wfp_log_list, svc_data_cache_kv, dns_hash);

					if (current_list == NULL)
					{
						// Initialize watcher
						current_list = NewDiffList();

						LIST *diff = UpdateDiffList(current_list, now_list, tick);

						// Do not use the result of diff
						FreeDiffList(diff);
					}
					else
					{
						// Update watcher
						LIST *diff = UpdateDiffList(current_list, now_list, tick);

						//Print("DIFF: %u\n", LIST_NUM(diff));

						// Classifying each of diff entries and insert them to the queue
						LockQueue(svc->ReportQueue);
						{
							UINT i;
							for (i = 0;i < LIST_NUM(diff);i++)
							{
								DIFF_ENTRY *e = (DIFF_ENTRY *)LIST_DATA(diff, i);

								bool ok = false;

								switch (e->Param)
								{
								case MS_THINFW_ENTRY_TYPE_PROCESS:
									DoNothing();
									MS_THINFW_ENTRY_PROCESS *proc = (MS_THINFW_ENTRY_PROCESS *)e->Data;

									//if (UniInStr(proc->ExeFilenameW, L"vpnclient_x64.exe"))
									//{
									//	Print("(B) %u %S %u %S\n", proc->ProcessId, proc->ExeFilenameW,
									//		proc->Rdp.SessionId, proc->Rdp.WinStationName);
									//}

									if (proc->ProcessId != current_process_id)
									{
										ok = true;
									}
									break;

								case MS_THINFW_ENTRY_TYPE_SERVICE:
									if (e->IsAdded) // Service: only new entries shall be reported
									{
										ok = true;
									}
									break;

								case MS_THINFW_ENTRY_TYPE_FILESHARE_SESSION:
									ok = true;
									break;

								case MS_THINFW_ENTRY_TYPE_FILESHARE_FILE:
									if (e->IsAdded) // File share: only new entries shall be reported
									{
										ok = true;
									}
									break;

								case MS_THINFW_ENTRY_TYPE_DNS:
									if (e->IsAdded) // DNS cache: only new entries shall be reported
									{
										ok = true;
									}
									break;

								case MS_THINFW_ENTRY_TYPE_BLOCK:
									if (e->IsAdded) // FW Block: only new entries shall be reported
									{
										ok = true;
									}
									break;

								case MS_THINFW_ENTRY_TYPE_TCP:
									if (e->IsAdded) // TCP process: only new entries shall be reported
									{
										MS_THINFW_ENTRY_TCP *tcp = (MS_THINFW_ENTRY_TCP *)e->Data;

										if (tcp->Tcp.Status != TCP_STATE_LISTEN &&
											(IsLocalHostIP(&tcp->Tcp.RemoteIP) || IsLocalHostIP(&tcp->Tcp.LocalIP) ||
											IsIPLocalHostOrMySelf(&tcp->Tcp.RemoteIP)))
										{
											// localhost: Do not report
										}
										else if (cfg_IgnoreDNSoverTCPSession && tcp->Tcp.RemotePort == NAT_DNS_PROXY_PORT && MsIsIpInDnsServerList(current_dns_servers_list, &tcp->Tcp.RemoteIP))
										{
											// DNS over TCP: Do not report
										}
										else
										{
											if (tcp->Process.ProcessId != current_process_id)
											{
												ok = true;
											}
										}
									}
									break;

								case MS_THINFW_ENTRY_TYPE_RDP:
									DoNothing();
									MS_THINFW_ENTRY_RDP *rdp = (MS_THINFW_ENTRY_RDP *)e->Data;

									if (IsLocalHostIP(&rdp->ClientIp) || IsIPLocalHostOrMySelf(&rdp->ClientIp))
									{
										// localhost: Do not report
									}
									else
									{
										ok = true;
									}
									break;
								}

								if (ok)
								{
									DIFF_ENTRY *e2 = CloneDiffEntry(e);

									e2->Flags = 0;
									if (is_locked)
									{
										e2->Flags |= MS_THINFW_ENTRY_FLAG_LOCKED;
									}

									if (svc->ReportQueue->num_item < cfg_ReportMaxQueueLength)
									{
										InsertQueue(svc->ReportQueue, e2);
									}
									else
									{
										Free(e2);
									}
								}
							}
						}
						UnlockQueue(svc->ReportQueue);

						FreeDiffList(diff);
					}

					FreeDiffList(now_list);
				}
				else
				{
					if (current_list != NULL)
					{
						// Free watcher
						FreeDiffList(current_list);
						current_list = NULL;
					}
				}
			}

			UINT fw_new_state = (config_revision & 0x0FFFFFFF) | (is_firewall_active ? 0x10000000 : 0);

			if (lastState_firewall != fw_new_state)
			{
				lastState_firewall = fw_new_state;

				if (cfg_Enable)
				{
					TfLog(svc, "Firewall active state is changed. New state is '%S' (Config revision: %u).",
						is_firewall_active ? "Active" : "Inactive", config_revision);
				}

				if (is_firewall_active == false)
				{
					bool old_state = svc->WfpEngine ? true : false;

					TfSetFirewall(svc, NULL, NULL);

					if (old_state)
					{
						TfLog(svc, "Clear all firewall rules from the Windows Kernel.");
					}
				}
				else
				{
					UINT num_rules_applied = 0;
					if (TfSetFirewall(svc, cfg_file_content, &num_rules_applied))
					{
						TfLog(svc, "Successfully inserted %u firewall rules to the Windows Kernel.", num_rules_applied);
					}
					else
					{
						TfLog(svc, "**Error** Failed to insert firewall rules to the Windows Kernel.");
					}
				}
			}
		}

		if (cfg_Enable)
		{
			if (last_regupdate == 0 || now >= (last_regupdate + (UINT64)THINFW_REG_UPDATE_INTERVAL))
			{
				TfUpdateReg(svc, false);
				last_regupdate = now;
			}
		}

		if (cfg_Enable)
		{
			if (cfg_EnableDailyAliveMessage)
			{
				UINT hh = (cfg_SendDailyAliveNoticeHhmmss % 1000000) / 10000;
				UINT mm = (cfg_SendDailyAliveNoticeHhmmss % 10000) / 100;
				UINT ss = (cfg_SendDailyAliveNoticeHhmmss % 100);

				SYSTEMTIME base_time_plus_hhmmss = CLEAN;
				base_time_plus_hhmmss.wYear = 1980;
				base_time_plus_hhmmss.wMonth = 1;
				base_time_plus_hhmmss.wDay = 1;
				base_time_plus_hhmmss.wHour = hh;
				base_time_plus_hhmmss.wMinute = mm;
				base_time_plus_hhmmss.wSecond = ss;

				UINT64 base_time_plus_hhmmss_64 = SystemToUINT64(&base_time_plus_hhmmss);

				UINT64 current_time_64 = LocalTime64();

				if (current_time_64 > base_time_plus_hhmmss_64)
				{
					UINT past_days_since_base = (UINT)((current_time_64 - base_time_plus_hhmmss_64) / (UINT64)(24 * 60 * 60 * 1000));

					if (last_past_days_since_base == 0)
					{
						last_past_days_since_base = past_days_since_base;
					}

					if (last_past_days_since_base != past_days_since_base)
					{
						last_past_days_since_base = past_days_since_base;

						TfRaiseAliveEvent(svc, false);
					}
				}
			}
		}

		UINT wait_interval = GetNextIntervalForInterrupt(im);

		if (wait_interval == 0)
		{
			wait_interval = 50;
		}

		Wait(svc->HaltEvent, wait_interval);
	}

	// Stop firewall
	TfSetFirewall(svc, NULL, NULL);

	if (current_list != NULL)
	{
		// Free watcher
		FreeDiffList(current_list);
		current_list = NULL;
	}

	// Free report thread
	svc->ReportThreadHaltFlag = true;
	Set(svc->ReportThreadHaltEvent);
	WaitThread(svc->ReportThread, INFINITE);
	ReleaseThread(svc->ReportThread);
	ReleaseEvent(svc->ReportThreadHaltEvent);

	if (cfg_Enable)
	{
		TfUpdateReg(svc, false);
	}

	while (true)
	{
		DIFF_ENTRY *e = GetNext(svc->ReportQueue);
		if (e == NULL)
		{
			break;
		}

		Free(e);
	}
	ReleaseQueue(svc->ReportQueue);

	FreeInterruptManager(im);

	FreeBuf(cfg_file_content);

	FreeIni(ini);

	MsFreeSidToUsernameCache(sid_cache);

	MsFreeDnsServersList(current_dns_servers_list);

	DuWfpStopLog2(wfp_log);

	MsFreeEventReaderSession(event_reader);

	if (current_single_instance != NULL)
	{
		FreeSingleInstance(current_single_instance);
		current_single_instance = NULL;
	}

	if (cfg_Enable)
	{
		TfLog(svc, "-------------------- Stop %S --------------------", svc->StartupSettings.AppTitle);
	}

	FreeKvListW(svc_data_cache_kv);

	MsFreeDnsHash(dns_hash);
}

void TfRaiseAliveEvent(TF_SERVICE *svc, bool is_startup)
{
	if (svc == NULL)
	{
		return;
	}

	UINT64 total_send_packets = 0;
	UINT64 total_send_bytes = 0;
	UINT64 total_recv_packets = 0;
	UINT64 total_recv_bytes = 0;
	char total_send_packets_str[32] = CLEAN;
	char total_send_bytes_str[32] = CLEAN;
	char total_recv_packets_str[32] = CLEAN;
	char total_recv_bytes_str[32] = CLEAN;

	UINT i;

	wchar_t tmp[2048];

	MS_ADAPTER_LIST *o;
	o = MsCreateAdapterList();

	if (o != NULL)
	{
		for (i = 0;i < o->Num;i++)
		{
			MS_ADAPTER *a = o->Adapters[i];

			total_send_packets += a->SendPacketsBroadcast + a->SendPacketsUnicast;
			total_send_bytes += a->SendBytes;

			total_recv_packets += a->RecvPacketsBroadcast + a->RecvPacketsUnicast;
			total_recv_bytes += a->RecvBytes;
		}

		MsFreeAdapterList(o);
	}

	ToStr3(total_send_packets_str, sizeof(total_send_packets_str), total_send_packets);
	ToStr3(total_send_bytes_str, sizeof(total_send_bytes_str), total_send_bytes);
	ToStr3(total_recv_packets_str, sizeof(total_recv_packets_str), total_recv_packets);
	ToStr3(total_recv_bytes_str, sizeof(total_recv_bytes_str), total_recv_bytes);

	// Get current MAC address
	char mac_str[24] = CLEAN;
	UCHAR mac[6] = CLEAN;

	UINT64 disk_free = 0;
	UINT64 disk_used = 0;
	UINT64 disk_total = 0;
	char disk_free_str[64] = CLEAN;
	char disk_used_str[64] = CLEAN;
	char disk_total_str[64] = CLEAN;
	char process_mem_usage_str[64] = CLEAN;

	PROCESS_MEMORY_COUNTERS meminfo = CLEAN;
	meminfo.cb = sizeof(meminfo);
	GetProcessMemoryInfo(GetCurrentProcess(), &meminfo, sizeof(meminfo));
	ToStr3(process_mem_usage_str, sizeof(process_mem_usage_str), meminfo.PagefileUsage);

	Win32GetDiskFree(MsGetWindowsDir(), &disk_free, &disk_used, &disk_total);
	ToStr3(disk_free_str, sizeof(disk_free_str), disk_free);
	ToStr3(disk_used_str, sizeof(disk_used_str), disk_used);
	ToStr3(disk_total_str, sizeof(disk_total_str), disk_total);

	StrCpy(mac_str, sizeof(mac_str), "(unknown)");

	if (TfGetCurrentMacAddress(mac))
	{
		BinToStr(mac_str, sizeof(mac_str), mac, 6);

		Copy(svc->MacAddress, mac, 6);
	}

	char ssl_lib_ver[MAX_PATH] = CLEAN;

	char timezone_str[16] = CLEAN;
	MsGetTimezoneSuffixStr(timezone_str, sizeof(timezone_str));

	char system_boot_datetime[128] = CLEAN;
	GetDateTimeStr64(system_boot_datetime, sizeof(system_boot_datetime), SystemToLocal64(MsGetWindowsBootSystemTime()));

	char system_boot_span[128] = CLEAN;
	GetSpanStrMilli(system_boot_span, sizeof(system_boot_span), MsGetTickCount64());

	char svc_boot_datetime[128] = CLEAN;
	GetDateTimeStr64(svc_boot_datetime, sizeof(svc_boot_datetime), svc->BootLocalTime);

	char svc_boot_span[128] = CLEAN;
	GetSpanStrMilli(svc_boot_span, sizeof(svc_boot_span), Tick64() - svc->BootTick);

	GetSslLibVersion(ssl_lib_ver, sizeof(ssl_lib_ver));

	if (is_startup)
	{
		TfLog(svc, "-------------------- Start %S --------------------", svc->StartupSettings.AppTitle);
	}
	else
	{
		TfLog(svc, "--- Daily Alive Message of %S ---", svc->StartupSettings.AppTitle);
	}

	TfLog(svc, "APP_NAME: %S", svc->StartupSettings.AppTitle);
	TfLog(svc, "THINFW_MODE: %S", svc->StartupSettings.Mode == TF_SVC_MODE_SYSTEMMODE ? "System Mode" : "User Mode");
	TfLog(svc, "THINFW_BOOT_DATETIME: %S%S", svc_boot_datetime, timezone_str);
	TfLog(svc, "THINFW_BOOT_UPTIME: %S", svc_boot_span);
	TfLog(svc, "CEDAR_VER: %u", CEDAR_VER);
	TfLog(svc, "CEDAR_BUILD: %u", CEDAR_BUILD);
	TfLog(svc, "BUILD_DATE: %04u/%02u/%02u %02u:%02u:%02u", BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D,
		BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE);
	TfLog(svc, "THINLIB_COMMIT_ID: %S", THINLIB_COMMIT_ID);
	TfLog(svc, "THINLIB_VER_LABEL: %S", THINLIB_VER_LABEL);
	TfLog(svc, "SSL_LIB_VER: %S", ssl_lib_ver);

	OS_INFO *os = GetOsInfo();
	if (os != NULL)
	{
		TfLog(svc, "OsType: %u", os->OsType);
		TfLog(svc, "OsServicePack: %u", os->OsServicePack);
		TfLog(svc, "OsSystemName: %S", os->OsSystemName);
		TfLog(svc, "OsProductName: %S", os->OsProductName);
		TfLog(svc, "OsVendorName: %S", os->OsVendorName);
		TfLog(svc, "OsVersion: %S", os->OsVersion);
		TfLog(svc, "KernelName: %S", os->KernelName);
		TfLog(svc, "KernelVersion: %S", os->KernelVersion);
	}

	TfLog(svc, "ComputerMacAddress: %S", mac_str);

	MEMINFO mem = CLEAN;
	GetMemInfo(&mem);

	TfLog(svc, "Memory - TotalVirtualMemory: %S bytes", mem.TotalMemory_Str);
	TfLog(svc, "Memory - UsedVirtualMemory: %S bytes", mem.UsedMemory_Str);
	TfLog(svc, "Memory - FreeVirtualMemory: %S bytes", mem.FreeMemory_Str);
	TfLog(svc, "Memory - TotalPhysMemory: %S bytes", mem.TotalPhys_Str);
	TfLog(svc, "Memory - UsedPhysMemory: %S bytes", mem.UsedPhys_Str);
	TfLog(svc, "Memory - FreePhysMemory: %S bytes", mem.FreePhys_Str);

	TfLog(svc, "SystemDisk - Free: %S bytes", disk_free_str);
	TfLog(svc, "SystemDisk - Used: %S bytes", disk_used_str);
	TfLog(svc, "SystemDisk - Total: %S bytes", disk_total_str);

	TfLog(svc, "Network - Total sent packets: %S packets", total_send_packets_str);
	TfLog(svc, "Network - Total sent data: %S bytes", total_send_bytes_str);
	TfLog(svc, "Network - Total received packets: %S packets", total_recv_packets_str);
	TfLog(svc, "Network - Total received data: %S bytes", total_recv_bytes_str);

	TfLog(svc, "Operating System Boot DateTime: %S%S", system_boot_datetime, timezone_str);
	TfLog(svc, "Operating System Uptime: %S", system_boot_span);

	TfLog(svc, "Memory usage of this process: %S bytes", process_mem_usage_str);

	wchar_t computer_name[128] = CLEAN;
	MsGetComputerNameFullEx(computer_name, sizeof(computer_name), true);

	UniFormat(tmp, sizeof(tmp), L"--Informational message-- %S is %S. Mode: %S, "
		L"THINFW_BOOT_DATETIME: %S%S, THINFW_BOOT_UPTIME: %S, "
		L"OsSystemName: %S, OsProductName: %S, OsVendorName: %S, "
		L"OsVersion: %S, "
		L"ComputerName: %s, "
		L"ComputerMacAddress: %S, "
		L"UserName: %s, "
		L"SystemDiskFree: %S bytes, SystemDiskUsed: %S bytes, SystemDiskTotal: %S bytes, "
		L"NetworkTotalSentPackets: %S packets, NetworkTotalSentData: %S bytes, NetworkTotalReceivedPackets: %S packets, NetworkTotalReceivedData: %S bytes, "
		L"TotalVirtualMemory: %S bytes, UsedVirtualMemory: %S bytes, FreeVirtualMemory: %S bytes, TotalPhysMemory: %S bytes, UsedPhysMemory:%S bytes, FreePhysMemory:%S bytes, ThinFwProcessAppPath: %s, ThinFwProcessMemoryUsage: %S bytes, "
		L"OsBootDateTime: %S%S, OsUptime: %S, "
		L"CEDAR_VER: %u, "
		L"CEDAR_BUILD: %u, BUILD_DATE: %04u/%02u/%02u %02u:%02u:%02u, "
		L"THINLIB_COMMIT_ID: %S, THINLIB_VER_LABEL: %S"
		,
		svc->StartupSettings.AppTitle,
		is_startup ? "started" : "working normally. This Daily Alive Message is sent by the EnableDailyAliveMessage flag",
		svc->StartupSettings.Mode == TF_SVC_MODE_SYSTEMMODE ? "System Mode" : "User Mode",
		svc_boot_datetime, timezone_str, svc_boot_span,
		os->OsSystemName, os->OsProductName, os->OsVendorName,
		os->OsVersion,
		computer_name,
		mac_str,
		svc->Username,
		disk_free_str, disk_used_str, disk_total_str,
		total_send_packets_str, total_send_bytes_str, total_recv_packets_str, total_recv_bytes_str,
		mem.TotalMemory_Str, mem.UsedMemory_Str, mem.FreeMemory_Str,
		mem.TotalPhys_Str, mem.UsedPhys_Str, mem.FreePhys_Str,
		MsGetExeFileNameW(),
		process_mem_usage_str,
		system_boot_datetime, timezone_str, system_boot_span,
		CEDAR_VER,
		CEDAR_BUILD, BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D,
		BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE,
		THINLIB_COMMIT_ID, THINLIB_VER_LABEL
	);

	TfInsertStrEvent(svc, tmp);
}

void TfThreadProc(THREAD *thread, void *param)
{
	if (thread == NULL || param == NULL)
	{
		return;
	}

	TF_SERVICE *svc = param;

	TfMain(svc);
}

void TfLog(TF_SERVICE *svc, char *format, ...)
{
	va_list args;
	char format2[MAX_SIZE * 2] = CLEAN;
	// 引数チェック
	if (format == NULL || svc == NULL)
	{
		return;
	}

	Format(format2, sizeof(format2), "[%s] %s", "ENGINE", format);

	va_start(args, format);

	TfLogMain(svc, format2, args);

	va_end(args);
}

void TfLogEx(TF_SERVICE *svc, char *prefix, char *format, ...)
{
	va_list args;
	char format2[MAX_SIZE * 2] = CLEAN;
	// 引数チェック
	if (format == NULL || svc == NULL)
	{
		return;
	}

	Format(format2, sizeof(format2), "[%s] %s", prefix, format);

	va_start(args, format);

	TfLogMain(svc, format2, args);

	va_end(args);
}

void TfLogMain(TF_SERVICE *svc, char *format, va_list args)
{
	UINT buf_tmp_size = 4096 * sizeof(wchar_t);
	if (format == NULL)
	{
		return;
	}

	wchar_t *buf3 = ZeroMalloc(buf_tmp_size);
	wchar_t *format_clone = CopyStrToUni(format);

	UniFormatArgs(buf3, buf_tmp_size, format_clone, args);

	if (svc != NULL && svc->Log != NULL)
	{
		InsertUnicodeRecord(svc->Log, buf3);
	}

	Debug("TF_LOG: %S\n", buf3);

	Free(buf3);
	Free(format_clone);
}

void TfStopService(TF_SERVICE *svc)
{
	if (svc == NULL)
	{
		return;
	}

	svc->HaltFlag = true;
	Set(svc->HaltEvent);

	WaitThread(svc->Thread, INFINITE);
	ReleaseThread(svc->Thread);

	ReleaseEvent(svc->HaltEvent);

	DeleteLock(svc->CurrentReportSettingsLock);
	DeleteLock(svc->EventIdEtcLock);

	FreeLog(svc->Log);

	Free(svc);
}

TF_SERVICE *TfStartService(TF_STARTUP_SETTINGS *settings)
{
	if (settings == NULL)
	{
		return NULL;
	}

	TF_SERVICE *svc = ZeroMalloc(sizeof(TF_SERVICE));

	UniStrCpy(svc->Username, sizeof(svc->Username), MsGetUserNameExW());

	Copy(&svc->StartupSettings, settings, sizeof(TF_STARTUP_SETTINGS));

	if (IsEmptyStr(svc->StartupSettings.AppTitle))
	{
		StrCpy(svc->StartupSettings.AppTitle, sizeof(svc->StartupSettings.AppTitle),
			"Thin Firewall System");
	}

	MakeDirEx(TF_LOG_DIR_NAME);

	svc->Log = NewLogEx(TF_LOG_DIR_NAME, "thinfw", LOG_SWITCH_DAY, false);
	svc->Log->Flush = true;

	svc->CurrentReportSettingsLock = NewLock();
	svc->EventIdEtcLock = NewLock();

	svc->HaltEvent = NewEvent();

	svc->Thread = NewThread(TfThreadProc, svc);

	return svc;
}

bool TfInstallDefaultConfig(wchar_t *filename, bool overwrite, bool set_acl, BUF *template_buf, char *mail_addr)
{
	bool free_template_buf = false;

	char init_mail_line[MAX_PATH] = CLEAN;

	if (StrLen(mail_addr) <= 5)
	{
		StrCpy(init_mail_line, sizeof(init_mail_line), "#ReportMailTo                    a@gmail.com");
	}
	else
	{
		Format(init_mail_line, sizeof(init_mail_line), "ReportMailTo                    %s", mail_addr);
	}

	char *eof_tag = "[END_OF_FILE]";

	if (filename == NULL)
	{
		return false;
	}

	wchar_t fullpath[MAX_PATH] = CLEAN;
	
	InnerFilePathW(fullpath, sizeof(fullpath), filename);

	bool exists = false;

	BUF *current_buf = ReadDumpW(fullpath);
	if (current_buf != NULL)
	{
		if (SearchBin(current_buf->Buf, 0, current_buf->Size, eof_tag, StrLen(eof_tag)) != INFINITE)
		{
			exists = true;
		}
		FreeBuf(current_buf);
	}

	if (overwrite == false && exists)
	{
		return false;
	}

	if (template_buf == NULL)
	{
		template_buf = ReadDump("|ThinFwDefaultConfig.txt");

		if (template_buf == NULL)
		{
			return false;
		}

		free_template_buf = true;
	}

	bool ret = false;

	BufSkipUtf8Bom(template_buf);

	BUF *template_buf2 = ReadRemainBuf(template_buf);

	if (template_buf2 != NULL)
	{
		SeekBufToEnd(template_buf2);
		WriteBufChar(template_buf2, 0);

		char *original_body = CopyStr(template_buf2->Buf);
		UINT original_body_size = StrSize(original_body);
		UINT tmp_body_size = original_body_size + 30000;

		char *tmp_body = ZeroMalloc(tmp_body_size);

		StrCpy(tmp_body, tmp_body_size, original_body);

		UINT rdp_port = DsGetRdpPortFromRegistry();
		if (rdp_port == 0)
		{
			rdp_port = DS_RDP_PORT;
		}

		char rdp_port_str[32] = CLEAN;
		ToStr(rdp_port_str, rdp_port);

		ReplaceStrEx(tmp_body, tmp_body_size, tmp_body, "$RDP_PORT$", rdp_port_str, false);
		ReplaceStrEx(tmp_body, tmp_body_size, tmp_body, "$MAIL_ADDR_LINE$", init_mail_line, false);

		UCHAR bom_data[] = { 0xef, 0xbb, 0xbf, };

		BUF *new_buf = NewBuf();
		WriteBuf(new_buf, bom_data, 3);
		WriteBuf(new_buf, tmp_body, StrLen(tmp_body));

		wchar_t dir[MAX_PATH] = CLEAN;
		GetDirNameFromFilePathW(dir, sizeof(dir), fullpath);

		MakeDirExW(dir);

		ret = DumpBufSafeW(new_buf, fullpath);

		if (ret)
		{
			if (set_acl)
			{
				MsSetFileSecureAclEverone(fullpath);
			}
		}

		FreeBuf(template_buf2);
		Free(original_body);
		Free(tmp_body);
		FreeBuf(new_buf);
	}

	if (free_template_buf)
	{
		FreeBuf(template_buf);
	}

	return ret;
}

#endif	// _WIN32

