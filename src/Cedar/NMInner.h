// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE IT IN OTHER COUNTRIES. IMPORTING THIS
// SOFTWARE INTO OTHER COUNTRIES IS AT YOUR OWN RISK. SOME COUNTRIES
// PROHIBIT ENCRYPTED COMMUNICATIONS. USING THIS SOFTWARE IN OTHER
// COUNTRIES MIGHT BE RESTRICTED.
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.


// NMInner.h
// The internal header of NM.c


// Constants
#define	NM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\User-mode Router Manager"
#define	NM_SETTING_REG_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\User-mode Router Manager\\Settings"

#define	NM_REFRESH_TIME			1000
#define	NM_NAT_REFRESH_TIME		1000
#define	NM_DHCP_REFRESH_TIME	1000

// Nat Admin structure
typedef struct NM
{
	CEDAR *Cedar;				// Cedar
} NM;

// Connection structure
typedef struct NM_CONNECT
{
	RPC *Rpc;					// RPC
	char *Hostname;
	UINT Port;
} NM_CONNECT;

// Login
typedef struct NM_LOGIN
{
	char *Hostname;
	UINT Port;
	UCHAR hashed_password[SHA1_SIZE];
} NM_LOGIN;

// Internal function
void InitNM();
void FreeNM();
void MainNM();
RPC *NmConnect(char *hostname, UINT port);
UINT NmConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT NmLogin(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmMainDlg(RPC *r);
UINT NmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmMainDlgInit(HWND hWnd, RPC *r);
void NmMainDlgRefresh(HWND hWnd, RPC *r);
void NmEditClientConfig(HWND hWnd, RPC *r);
void NmEditVhOption(HWND hWnd, SM_HUB *r);
UINT NmEditVhOptionProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmEditVhOptionInit(HWND hWnd, SM_HUB *r);
void NmEditVhOptionUpdate(HWND hWnd, SM_HUB *r);
void NmEditVhOptionOnOk(HWND hWnd, SM_HUB *r);
void NmEditVhOptionFormToVH(HWND hWnd, VH_OPTION *t);
bool NmStatus(HWND hWnd, SM_SERVER *s, void *param);
bool NmInfo(HWND hWnd, SM_SERVER *s, void *param);
void NmNat(HWND hWnd, SM_HUB *r);
UINT NmNatProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmNatInit(HWND hWnd, SM_HUB *r);
void NmNatRefresh(HWND hWnd, SM_HUB *r);
void NmDhcp(HWND hWnd, SM_HUB *r);
UINT NmDhcpProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmDhcpRefresh(HWND hWnd, SM_HUB *r);
void NmDhcpInit(HWND hWnd, SM_HUB *r);
void NmChangePassword(HWND hWnd, RPC *r);
UINT NmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
