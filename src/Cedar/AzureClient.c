﻿// IPA-DN-ThinLib Library Source Code
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


// AzureClient.c
// VPN Azure Client

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Wait for connection request
void AcWaitForRequest(AZURE_CLIENT *ac, SOCK *s, AZURE_PARAM *param)
{
	// Validate arguments
	if (ac == NULL || s == NULL || param == NULL)
	{
		return;
	}

	while (ac->Halt == false)
	{
		UCHAR uc;

		// Receive 1 byte
		if (RecvAll(s, &uc, 1, false) == 0)
		{
			break;
		}

		if (uc != 0)
		{
			// Receive a Pack
			PACK *p = RecvPackWithHash(s);

			if (p == NULL)
			{
				break;
			}
			else
			{
				// Verify contents of Pack
				char opcode[MAX_SIZE];
				char cipher_name[MAX_SIZE];
				char hostname[MAX_SIZE];

				PackGetStr(p, "opcode", opcode, sizeof(opcode));
				PackGetStr(p, "cipher_name", cipher_name, sizeof(cipher_name));
				PackGetStr(p, "hostname", hostname, sizeof(hostname));

				if (StrCmpi(opcode, "relay") == 0)
				{
					IP client_ip, server_ip;
					UINT client_port;
					UINT server_port;
					UCHAR session_id[SHA1_SIZE];

					if (PackGetIp(p, "client_ip", &client_ip) &&
						PackGetIp(p, "server_ip", &server_ip) &&
						PackGetData2(p, "session_id", session_id, sizeof(session_id)))
					{
						client_port = PackGetInt(p, "client_port");
						server_port = PackGetInt(p, "server_port");

						if (client_port != 0 && server_port != 0)
						{
							SOCK *ns;
							Debug("Connect Request from %r:%u\n", &client_ip, client_port);

							// Create new socket and connect VPN Azure Server
							if (ac->DDnsStatusCopy.InternetSetting.ProxyType == PROXY_DIRECT)
							{
								ns = ConnectEx2(ac->DDnsStatusCopy.CurrentAzureIp, AZURE_SERVER_PORT,
									0, (bool *)&ac->Halt);
							}
							else
							{
								ns = WpcSockConnect2(ac->DDnsStatusCopy.CurrentAzureIp, AZURE_SERVER_PORT,
									&ac->DDnsStatusCopy.InternetSetting, NULL, AZURE_VIA_PROXY_TIMEOUT);
							}

							if (ns == NULL)
							{
								Debug("Connect Error.\n");
							}
							else
							{
								Debug("Connected to the relay server.\n");

								SetTimeout(ns, param->DataTimeout);

								if (StartSSLEx(ns, NULL, NULL, true, 0, NULL))
								{
									// Check certification
									char server_cert_hash_str[MAX_SIZE];
									UCHAR server_cert_hash[SHA1_SIZE];

									Zero(server_cert_hash, sizeof(server_cert_hash));
									GetXDigest(ns->RemoteX, server_cert_hash, true);

									BinToStr(server_cert_hash_str, sizeof(server_cert_hash_str),
										server_cert_hash, SHA1_SIZE);

									if (IsEmptyStr(ac->DDnsStatusCopy.AzureCertHash) || StrCmpi(server_cert_hash_str, ac->DDnsStatusCopy.AzureCertHash) == 0
										 || StrCmpi(server_cert_hash_str, ac->DDnsStatus.AzureCertHash) == 0)
									{
										if (SendAll(ns, AZURE_PROTOCOL_DATA_SIANGTURE, 24, true))
										{
											PACK *p2 = NewPack();

											PackAddStr(p2, "hostname", hostname);
											PackAddData(p2, "session_id", session_id, sizeof(session_id));

											if (SendPackWithHash(ns, p2))
											{
												UCHAR uc;

												if (RecvAll(ns, &uc, 1, true) != false)
												{
													if (uc != 0)
													{
														SOCK *accept_sock = GetReverseListeningSock(ac->Cedar);

														if (accept_sock != NULL)
														{
															AddRef(ns->ref);

															SetTimeout(ns, INFINITE);

															Copy(&ns->Reverse_MyServerGlobalIp, &server_ip, sizeof(IP));
															ns->Reverse_MyServerPort = server_port;

															InjectNewReverseSocketToAccept(accept_sock, ns,
																&client_ip, client_port);

															ReleaseSock(accept_sock);
														}
													}
												}
											}

											FreePack(p2);
										}
									}
								}

								ReleaseSock(ns);
							}
						}
					}
				}

				FreePack(p);
			}
		}

		// Send 1 byte
		uc = 0;
		if (SendAll(s, &uc, 1, false) == 0)
		{
			break;
		}
	}
}

// VPN Azure client main thread
void AcMainThread(THREAD *thread, void *param)
{
	AZURE_CLIENT *ac = (AZURE_CLIENT *)param;
	UINT last_ip_revision = INFINITE;
	UINT64 last_reconnect_tick = 0;
	UINT64 next_reconnect_interval = AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
	UINT num_reconnect_retry = 0;
	UINT64 next_ddns_retry_tick = 0;
	bool last_connect_ok = false;
	// Validate arguments
	if (ac == NULL || thread == NULL)
	{
		return;
	}

	while (ac->Halt == false)
	{
		UINT64 now = Tick64();
		bool connect_was_ok = false;
		// Wait for enabling VPN Azure function
		if (ac->IsEnabled)
		{
			// VPN Azure is enabled
			DDNS_CLIENT_STATUS st;
			bool connect_now = false;
			bool azure_ip_changed = false;

			Lock(ac->Lock);
			{
				Copy(&st, &ac->DDnsStatus, sizeof(DDNS_CLIENT_STATUS));

				if (StrCmpi(st.CurrentAzureIp, ac->DDnsStatusCopy.CurrentAzureIp) != 0)
				{
					if (IsEmptyStr(st.CurrentAzureIp) == false)
					{
						// Destination IP address is changed
						connect_now = true;
						num_reconnect_retry = 0;
					}
				}

				if (StrCmpi(st.CurrentHostName, ac->DDnsStatusCopy.CurrentHostName) != 0)
				{
					// DDNS host name is changed
					connect_now = true;
					num_reconnect_retry = 0;
				}

				Copy(&ac->DDnsStatusCopy, &st, sizeof(DDNS_CLIENT_STATUS));
			}
			Unlock(ac->Lock);

			if (last_ip_revision != ac->IpStatusRevision)
			{
				last_ip_revision = ac->IpStatusRevision;

				connect_now = true;

				num_reconnect_retry = 0;
			}

			if (last_reconnect_tick == 0 || (now >= (last_reconnect_tick + next_reconnect_interval)))
			{
				UINT r;

				last_reconnect_tick = now;
				num_reconnect_retry++;
				next_reconnect_interval = (UINT64)num_reconnect_retry * AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
				next_reconnect_interval = MIN(next_reconnect_interval, AZURE_CONNECT_MAX_RETRY_INTERVAL);

				r = (UINT)next_reconnect_interval;

				r = GenRandInterval(r / 2, r);

				next_reconnect_interval = r;

				connect_now = true;
			}

			if (IsEmptyStr(st.CurrentAzureIp) == false && IsEmptyStr(st.CurrentHostName) == false)
			{
				if (connect_now)
				{
					SOCK *s;
					char *host = NULL;
					UINT port = AZURE_SERVER_PORT;

					Debug("VPN Azure: Connecting to %s...\n", st.CurrentAzureIp);

					if (ParseHostPort(st.CurrentAzureIp, &host, &port, AZURE_SERVER_PORT))
					{
						if (st.InternetSetting.ProxyType == PROXY_DIRECT)
						{
							s = ConnectEx2(host, port, 0, (bool *)&ac->Halt);
						}
						else
						{
							s = WpcSockConnect2(host, port, &st.InternetSetting, NULL, AZURE_VIA_PROXY_TIMEOUT);
						}

						if (s != NULL)
						{
							PACK *p;
							UINT64 established_tick = 0;

							Debug("VPN Azure: Connected.\n");

							SetTimeout(s, AZURE_PROTOCOL_CONTROL_TIMEOUT_DEFAULT);

							Lock(ac->Lock);
							{
								ac->CurrentSock = s;
								ac->IsConnected = true;
								StrCpy(ac->ConnectingAzureIp, sizeof(ac->ConnectingAzureIp), st.CurrentAzureIp);
							}
							Unlock(ac->Lock);

							SendAll(s, AZURE_PROTOCOL_CONTROL_SIGNATURE, StrLen(AZURE_PROTOCOL_CONTROL_SIGNATURE), false);

							// Receive parameter
							p = RecvPackWithHash(s);
							if (p != NULL)
							{
								UCHAR c;
								AZURE_PARAM param;
								bool hostname_changed = false;

								Zero(&param, sizeof(param));

								param.ControlKeepAlive = PackGetInt(p, "ControlKeepAlive");
								param.ControlTimeout = PackGetInt(p, "ControlTimeout");
								param.DataTimeout = PackGetInt(p, "DataTimeout");
								param.SslTimeout = PackGetInt(p, "SslTimeout");

								FreePack(p);

								param.ControlKeepAlive = MAKESURE(param.ControlKeepAlive, 1000, AZURE_SERVER_MAX_KEEPALIVE);
								param.ControlTimeout = MAKESURE(param.ControlTimeout, 1000, AZURE_SERVER_MAX_TIMEOUT);
								param.DataTimeout = MAKESURE(param.DataTimeout, 1000, AZURE_SERVER_MAX_TIMEOUT);
								param.SslTimeout = MAKESURE(param.SslTimeout, 1000, AZURE_SERVER_MAX_TIMEOUT);

								Lock(ac->Lock);
								{
									Copy(&ac->AzureParam, &param, sizeof(AZURE_PARAM));
								}
								Unlock(ac->Lock);

								SetTimeout(s, param.ControlTimeout);

								// Send parameter
								p = NewPack();
								PackAddStr(p, "CurrentHostName", st.CurrentHostName);
								PackAddStr(p, "CurrentAzureIp", st.CurrentAzureIp);
								PackAddInt64(p, "CurrentAzureTimestamp", st.CurrentAzureTimestamp);
								PackAddStr(p, "CurrentAzureSignature", st.CurrentAzureSignature);

								Lock(ac->Lock);
								{
									if (StrCmpi(st.CurrentHostName, ac->DDnsStatus.CurrentHostName) != 0)
									{
										hostname_changed = true;
									}
								}
								Unlock(ac->Lock);

								if (hostname_changed == false)
								{
									if (SendPackWithHash(s, p))
									{
										// Receive result
										if (RecvAll(s, &c, 1, false))
										{
											if (c && ac->Halt == false)
											{
												connect_was_ok = true;

												established_tick = Tick64();

												AcWaitForRequest(ac, s, &param);
											}
										}
									}
								}

								FreePack(p);
							}
							else
							{
								WHERE;
							}

							Debug("VPN Azure: Disconnected.\n");

							Lock(ac->Lock);
							{
								ac->IsConnected = false;
								ac->CurrentSock = NULL;
								ClearStr(ac->ConnectingAzureIp, sizeof(ac->ConnectingAzureIp));
							}
							Unlock(ac->Lock);

							if (established_tick != 0)
							{
								if ((established_tick + (UINT64)AZURE_CONNECT_MAX_RETRY_INTERVAL) <= Tick64())
								{
									// If the connected time exceeds the AZURE_CONNECT_MAX_RETRY_INTERVAL, reset the retry counter.
									last_reconnect_tick = 0;
									num_reconnect_retry = 0;
									next_reconnect_interval = AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
								}
							}

							Disconnect(s);
							ReleaseSock(s);
						}
						else
						{
							Debug("VPN Azure: Error: Connect Failed.\n");
						}

						Free(host);
					}
				}
			}
		}
		else
		{
			last_reconnect_tick = 0;
			num_reconnect_retry = 0;
			next_reconnect_interval = AZURE_CONNECT_INITIAL_RETRY_INTERVAL;
		}

		if (ac->Halt)
		{
			break;
		}

		if (connect_was_ok)
		{
			// If connection goes out after connected, increment connection success count to urge DDNS client query
			next_ddns_retry_tick = Tick64() + MIN((UINT64)DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF * (UINT64)(num_reconnect_retry + 1), (UINT64)DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF_MAX);
		}

		if ((next_ddns_retry_tick != 0) && (Tick64() >= next_ddns_retry_tick))
		{
			next_ddns_retry_tick = 0;

			ac->DDnsTriggerInt++;
		}

		Wait(ac->Event, rand() % 1000);
	}
}

// Get enabled or disabled VPN Azure client
bool AcGetEnable(AZURE_CLIENT *ac)
{
	// Validate arguments
	if (ac == NULL)
	{
		return false;
	}

	return ac->IsEnabled;
}

// Enable or disable VPN Azure client
void AcSetEnable(AZURE_CLIENT *ac, bool enabled)
{
	bool old_status;
	// Validate arguments
	if (ac == NULL)
	{
		return;
	}

	old_status = ac->IsEnabled;

	ac->IsEnabled = enabled;

	if (ac->IsEnabled && (ac->IsEnabled != old_status))
	{
		ac->DDnsTriggerInt++;
	}

	AcApplyCurrentConfig(ac, NULL);
}

// Set current configuration to VPN Azure client
void AcApplyCurrentConfig(AZURE_CLIENT *ac, DDNS_CLIENT_STATUS *ddns_status)
{
	bool disconnect_now = false;
	SOCK *disconnect_sock = NULL;
	// Validate arguments
	if (ac == NULL)
	{
		return;
	}

	// Get current DDNS configuration
	Lock(ac->Lock);
	{
		if (ddns_status != NULL)
		{
			if (StrCmpi(ac->DDnsStatus.CurrentHostName, ddns_status->CurrentHostName) != 0)
			{
				// If host name is changed, disconnect current data connection
				disconnect_now = true;
			}

			if (Cmp(&ac->DDnsStatus.InternetSetting, &ddns_status->InternetSetting, sizeof(INTERNET_SETTING)) != 0)
			{
				// If proxy setting is changed, disconnect current data connection
				disconnect_now = true;
			}

			Copy(&ac->DDnsStatus, ddns_status, sizeof(DDNS_CLIENT_STATUS));
		}

		if (ac->IsEnabled == false)
		{
			// If VPN Azure client is disabled, disconnect current data connection
			disconnect_now = true;
		}

		if (disconnect_now)
		{
			if (ac->CurrentSock != NULL)
			{
				disconnect_sock = ac->CurrentSock;
				AddRef(disconnect_sock->ref);
			}
		}
	}
	Unlock(ac->Lock);

	if (disconnect_sock != NULL)
	{
		Disconnect(disconnect_sock);
		ReleaseSock(disconnect_sock);
	}

	Set(ac->Event);
}

// Free VPN Azure client
void FreeAzureClient(AZURE_CLIENT *ac)
{
	SOCK *disconnect_sock = NULL;
	// Validate arguments
	if (ac == NULL)
	{
		return;
	}

	ac->Halt = true;

	Lock(ac->Lock);
	{
		if (ac->CurrentSock != NULL)
		{
			disconnect_sock = ac->CurrentSock;

			AddRef(disconnect_sock->ref);
		}
	}
	Unlock(ac->Lock);

	if (disconnect_sock != NULL)
	{
		Disconnect(disconnect_sock);
		ReleaseSock(disconnect_sock);
	}

	Set(ac->Event);

	// Stop main thread
	WaitThread(ac->MainThread, INFINITE);
	ReleaseThread(ac->MainThread);

	ReleaseEvent(ac->Event);

	DeleteLock(ac->Lock);

	Free(ac);
}

// Create new VPN Azure client
AZURE_CLIENT *NewAzureClient(CEDAR *cedar, SERVER *server)
{
	AZURE_CLIENT *ac;
	// Validate arguments
	if (cedar == NULL || server == NULL)
	{
		return NULL;
	}

	ac = ZeroMalloc(sizeof(AZURE_CLIENT));

	ac->Cedar = cedar;

	ac->Server = server;

	ac->Lock = NewLock();

	ac->IsEnabled = false;

	ac->Event = NewEvent();

	// Start main thread
	ac->MainThread = NewThread(AcMainThread, ac);

	return ac;
}

