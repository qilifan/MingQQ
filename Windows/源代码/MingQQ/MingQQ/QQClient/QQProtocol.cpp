#include "StdAfx.h"
#include "QQProtocol.h"

#define	MAX_URL_LEN		3072		// 2048+1024

CQQProtocol::CQQProtocol(void)
{
}

CQQProtocol::~CQQProtocol(void)
{
}

// 检测是否需要输入验证码
BOOL CQQProtocol::CheckVerifyCode(CHttpClient& HttpClient, LPCTSTR lpQQNum, 
								  LPCTSTR lpAppId, CVerifyCodeInfo * lpVCInfo)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=1&login_state=10&t=20130723001\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("https://ssl.ptlogin2.qq.com/check?uin=%s&appid=%s&js_ver=10038&js_type=0&login_sig=P9011ArgB3ImUQV*BfKuftIu9o3lGeuIoBVBi*WjElOnOl2OzVIzg3gHjE0KJ9e3&u1=http%%3A%%2F%%2Fweb2.qq.com%%2Floginproxy.html&r=0.1790402590984438");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpQQNum || NULL == lpAppId || NULL == lpVCInfo)
		return FALSE;

	wsprintf(szUrl, lpFmt, lpQQNum, lpAppId);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpVCInfo->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取验证码图片
BOOL CQQProtocol::GetVerifyCodePic(CHttpClient& HttpClient, LPCTSTR lpAppId, 
								   LPCTSTR lpQQNum, LPCTSTR lpVCType, CBuffer * lpVerifyCodePic)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=1&login_state=10&t=20130723001\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("https://ssl.captcha.qq.com/getimage?aid=%s&r=0.43951176664325314&uin=%s");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpAppId || NULL == lpQQNum 
		|| NULL == lpVCType || NULL == lpVerifyCodePic)
		return FALSE;

	wsprintf(szUrl, lpFmt, lpAppId, lpQQNum);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	lpVerifyCodePic->Release();
	bRet = lpVerifyCodePic->Add(RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 第一次登录
BOOL CQQProtocol::Login1(CHttpClient& HttpClient, LPCTSTR lpQQNum, LPCTSTR lpQQPwd,	
						 LPCTSTR lpVerifyCode, const CHAR * lpPtUin, int nPtUin, 
						 LPCTSTR lpAppId, CLoginResult_1 * lpLoginResult1)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=1&login_state=10&t=20130723001\r\nAccept-Language: zh-cn\r\n");
// 	LPCTSTR lpFmt = _T("https://ssl.ptlogin2.qq.com/login?u=%s&p=%s&verifycode=%s\
// 		&webqq_type=10&remember_uin=1&login2qq=1&aid=%s&u1=http%%3A%%2F%%2Fweb.qq.com\
// 		%%2Floginproxy.html%%3Flogin2qq%%3D1%%26webqq_type%%3D10&h=1&ptredirect=0&ptlang\
// 		=2052&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=1-8-4593&mibao_css=m_webqq&t=1&g=1");
	LPCTSTR lpFmt = _T("https://ssl.ptlogin2.qq.com/login?u=%s&p=%s&verifycode=%s\
		&webqq_type=10&remember_uin=1&login2qq=1&aid=%s&u1=http%%3A%%2F%%2Fweb2.qq.com\
		%%2Floginproxy.html%%3Flogin2qq%%3D1%%26webqq_type%%3D10&h=1&ptredirect=0&ptlang=2052\
		&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=3-13-11750&mibao_css=m_webqq\
		&t=1&g=1&js_type=0&js_ver=10038&login_sig=P9011ArgB3ImUQV*BfKuftIu9o3lGeuIoBVBi*WjElOnOl2OzVIzg3gHjE0KJ9e3");
	TCHAR szQQNum[32] = {0}, szQQPwd[32] = {0}, szVerifyCode[32] = {0};
	TCHAR szPwdHash[64] = {0};
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	std::vector<tstring> arrRespHeader;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpQQNum || NULL == lpQQPwd || NULL == lpVerifyCode 
		|| NULL == lpPtUin || nPtUin <= 0 || NULL == lpAppId || NULL == lpLoginResult1)
		return FALSE;
	
	_tcsncpy(szQQNum, lpQQNum, sizeof(szQQNum)/sizeof(TCHAR)-1);
	_tcsncpy(szQQPwd, lpQQPwd, sizeof(szQQPwd)/sizeof(TCHAR)-1);
	_tcsncpy(szVerifyCode, lpVerifyCode, sizeof(szVerifyCode)/sizeof(TCHAR)-1);

	CalcPwdHash(lpQQPwd, szVerifyCode, lpPtUin, nPtUin, szPwdHash, sizeof(szPwdHash)/sizeof(TCHAR));

	wsprintf(szUrl, lpFmt, szQQNum, szPwdHash, szVerifyCode, lpAppId);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, &arrRespHeader, RespData);
	if (!bRet || dwRespCode != 200)
	{
		arrRespHeader.clear();
		return FALSE;
	}

	bRet = lpLoginResult1->Parse(&RespData, &arrRespHeader);
	if (!bRet)
	{
		arrRespHeader.clear();
		return FALSE;
	}

	arrRespHeader.clear();

	if (0 == lpLoginResult1->m_nRetCode)	// 登录成功
	{
		bRet = HttpGet(HttpClient, lpLoginResult1->m_strCheckSigUrl.c_str(), 
			lpszReqHeaders, dwRespCode, &arrRespHeader, RespData);
		if (!bRet || dwRespCode != 200)
		{
			arrRespHeader.clear();
			return FALSE;
		}
	}

	arrRespHeader.clear();

	return TRUE;
}

// 第二次登录
BOOL CQQProtocol::Login2(CHttpClient& HttpClient, QQ_STATUS nQQStatus, 
						 LPCTSTR lpPtWebQq, LPCTSTR lpClientId, 
						 CLoginResult_2 * lpLoginResult2)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2&id=3\r\nContent-Type: application/x-www-form-urlencoded\r\n");
	LPCTSTR lpszUrl = _T("http://d.web2.qq.com/channel/login2");
	LPCTSTR lpFmt1 = _T("{\"status\":\"%s\",\"ptwebqq\":\"%s\",\"passwd_sig\":\"\",\"clientid\":\"%s\",\"psessionid\":null}");
	LPCSTR lpFmt2 = "r=%s&clientid=%s&psessionid=null";
	LPCTSTR lpStatusStr;
	TCHAR cRData[2048] = {0};
	std::string strRData, strClientId;
	CHAR cPostData[4096] = {0};
	int nPostDataLen;
	DWORD dwRespCode;
	std::vector<tstring> arrRespHeader;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpPtWebQq || NULL == lpClientId || NULL == lpLoginResult2)
		return FALSE;

	lpStatusStr = ConvertToQQStatusStr(nQQStatus);

	wsprintf(cRData, lpFmt1, lpStatusStr, lpPtWebQq, lpClientId);
	strRData = EncodeData(cRData, _tcslen(cRData));

	strClientId = EncodeData(lpClientId, _tcslen(lpClientId));

	sprintf(cPostData, lpFmt2, strRData.c_str(), strClientId.c_str());
	nPostDataLen = strlen(cPostData);

	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, cPostData, 
		nPostDataLen, dwRespCode, &arrRespHeader, RespData);
	if (!bRet || dwRespCode != 200)
	{
		arrRespHeader.clear();
		return FALSE;
	}

	bRet = lpLoginResult2->Parse(&RespData, &arrRespHeader);
	if (!bRet)
	{
		arrRespHeader.clear();
		return FALSE;
	}

	return TRUE;
}

// 注销
BOOL CQQProtocol::Logout(CHttpClient& HttpClient, LPCTSTR lpClientId, 
						 LPCTSTR lpPSessionId, CLogoutResult * lpLogoutResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/logout2?ids=12916&clientid=%s&psessionid=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpClientId || NULL == lpPSessionId || NULL == lpLogoutResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, lpClientId, lpPSessionId, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpLogoutResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取好友列表
BOOL CQQProtocol::GetBuddyList(CHttpClient& HttpClient, UINT nQQUin,
							   LPCTSTR lpPtWebQq, LPCTSTR lpVfWebQq, 
							   CBuddyListResult * lpResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=3\r\nContent-Type: application/x-www-form-urlencoded\r\n");
	LPCTSTR lpszUrl = _T("http://s.web2.qq.com/api/get_user_friends2");
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpPtWebQq || NULL == lpVfWebQq || NULL == lpResult)
		return FALSE;

	CHAR * lpText = UnicodeToUtf8(lpVfWebQq);
	if (NULL == lpText)
		return FALSE;
	std::string strVfWebQq = lpText;
	delete []lpText;

	std::string strHash = CalcHash(nQQUin, lpPtWebQq);

	std::string strPostData;

	strPostData = "{\"h\":\"hello\",\"hash\":\"";
	strPostData += strHash;
	strPostData += "\",\"vfwebqq\":\"";
	strPostData += strVfWebQq;
	strPostData += "\"}";

	strPostData = EncodeData(strPostData.c_str(), strPostData.size());
	strPostData = "r=" + strPostData;

	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, 
		strPostData.c_str(), strPostData.size(), dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取在线好友列表
BOOL CQQProtocol::GetOnlineBuddyList(CHttpClient& HttpClient, LPCTSTR lpClientId, 
									 LPCTSTR lpPSessionId, COnlineBuddyListResult * lpResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/get_online_buddies2?clientid=%s&psessionid=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpClientId || NULL == lpPSessionId || NULL == lpResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, lpClientId, lpPSessionId, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取群列表
BOOL CQQProtocol::GetGroupList(CHttpClient& HttpClient, int nQQUin, 
							   LPCTSTR lpPtWebQq, LPCTSTR lpVfWebQq, 
							   CGroupListResult * lpResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
	LPCTSTR lpszUrl = _T("http://s.web2.qq.com/api/get_group_name_list_mask2");
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpResult)
		return FALSE;

	CHAR * lpText = UnicodeToUtf8(lpVfWebQq);
	if (NULL == lpText)
		return FALSE;
	std::string strVfWebQq = lpText;
	delete []lpText;

	std::string strHash = CalcHash(nQQUin, lpPtWebQq);

	std::string strPostData;

	strPostData = "{\"vfwebqq\":\"";
	strPostData += strVfWebQq;
	strPostData += "\",\"hash\":\"";
	strPostData += strHash;
	strPostData += "\"}";

	strPostData = EncodeData(strPostData.c_str(), strPostData.size());
	strPostData = "r=" + strPostData;

	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, 
		strPostData.c_str(), strPostData.size(), dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取最近联系人列表
BOOL CQQProtocol::GetRecentList(CHttpClient& HttpClient, LPCTSTR lpVfWebQq, 
								LPCTSTR lpClientId, LPCTSTR lpPSessionId, CRecentListResult * lpResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
	LPCTSTR lpszUrl = _T("http://d.web2.qq.com/channel/get_recent_list2");
	LPCTSTR lpFmt1 = _T("{\"vfwebqq\":\"%s\",\"clientid\":\"%s\",\"psessionid\":\"%s\"}");
	LPCSTR lpFmt2 = "r=%s&clientid=%s&psessionid=%s";
	TCHAR cRData[2048] = {0};
	std::string strRData, strClientId, strPSessionId;
	CHAR cPostData[4096] = {0};
	int nPostDataLen;
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpClientId || 
		NULL == lpPSessionId || NULL == lpResult)
		return FALSE;

	wsprintf(cRData, lpFmt1, lpVfWebQq, lpClientId, lpPSessionId);
	strRData = EncodeData(cRData, _tcslen(cRData));

	strClientId = EncodeData(lpClientId, _tcslen(lpClientId));
	strPSessionId = EncodeData(lpPSessionId, _tcslen(lpPSessionId));
	
	sprintf(cPostData, lpFmt2, strRData.c_str(), strClientId.c_str(), strPSessionId.c_str());
	nPostDataLen = strlen(cPostData);

	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, cPostData, 
		nPostDataLen, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 轮询消息
BOOL CQQProtocol::Poll(CHttpClient& HttpClient, LPCTSTR lpClientId,	
					   LPCTSTR lpPSessionId, CBuffer * lpResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
	LPCTSTR lpszUrl = _T("http://d.web2.qq.com/channel/poll2");
	LPCTSTR lpFmt1 = _T("{\"clientid\":\"%s\",\"psessionid\":\"%s\",\"key\":0,\"ids\":[]}");
	LPCSTR lpFmt2 = "r=%s&clientid=%s&psessionid=%s";
	TCHAR cRData[2048] = {0};
	std::string strRData, strClientId, strPSessionId;
	CHAR cPostData[4096] = {0};
	int nPostDataLen;
	DWORD dwRespCode;
	BOOL bRet;

	if (NULL == lpClientId || NULL == lpPSessionId || NULL == lpResult)
		return FALSE;

	lpResult->Release();

	wsprintf(cRData, lpFmt1, lpClientId, lpPSessionId);
	strRData = EncodeData(cRData, _tcslen(cRData));

	strClientId = EncodeData(lpClientId, _tcslen(lpClientId));
	strPSessionId = EncodeData(lpPSessionId, _tcslen(lpPSessionId));
	
	sprintf(cPostData, lpFmt2, strRData.c_str(), strClientId.c_str(), strPSessionId.c_str());
	nPostDataLen = strlen(cPostData);

	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, cPostData, 
		nPostDataLen, dwRespCode, NULL, *lpResult);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	return TRUE;
}

// 获取好友信息
BOOL CQQProtocol::GetBuddyInfo(CHttpClient& HttpClient, UINT nQQUin, 
							   LPCTSTR lpVfWebQq, CBuddyInfoResult * lpBuddyInfoResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://s.web2.qq.com/api/get_friend_info2?tuin=%u&verifysession=&code=&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpBuddyInfoResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nQQUin, lpVfWebQq, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpBuddyInfoResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取陌生人信息
BOOL CQQProtocol::GetStrangerInfo(CHttpClient& HttpClient, UINT nQQUin,	
								  LPCTSTR lpVfWebQq, CBuddyInfoResult * lpBuddyInfoResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://s.web2.qq.com/api/get_stranger_info2?tuin=%u&verifysession=&gid=0&code=&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpBuddyInfoResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nQQUin, lpVfWebQq, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpBuddyInfoResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取群信息
BOOL CQQProtocol::GetGroupInfo(CHttpClient& HttpClient, UINT nGroupCode,
							   LPCTSTR lpVfWebQq, CGroupInfoResult * lpGroupInfoResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://s.web2.qq.com/api/get_group_info_ext2?gcode=%u&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpGroupInfoResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nGroupCode, lpVfWebQq, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpGroupInfoResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取好友、群成员或群号码
BOOL CQQProtocol::GetQQNum(CHttpClient& HttpClient, BOOL bIsBuddy, UINT nQQUin, 
						   LPCTSTR lpVfWebQq, CGetQQNumResult * lpGetQQNumResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://s.web2.qq.com/api/get_friend_uin2?tuin=%u&verifysession=&type=%d&code=&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	int nType;
	time_t t;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpGetQQNumResult)
		return FALSE;

	nType = bIsBuddy ? 1 : 4;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nQQUin, nType, lpVfWebQq, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpGetQQNumResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取QQ个性签名
BOOL CQQProtocol::GetQQSign(CHttpClient& HttpClient, UINT nQQUin,
							LPCTSTR lpVfWebQq, CGetSignResult * lpGetSignResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://s.web2.qq.com/api/get_single_long_nick2?tuin=%u&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpGetSignResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nQQUin, lpVfWebQq, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpGetSignResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 设置QQ个性签名
BOOL CQQProtocol::SetQQSign(CHttpClient& HttpClient, LPCTSTR lpSign, 
							LPCTSTR lpVfWebQq, CSetSignResult * lpSetSignResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
	LPCTSTR lpszUrl = _T("http://s.web2.qq.com/api/set_long_nick2");
	LPCTSTR lpFmt1 = _T("{\"nlk\":\"%s\",\"vfwebqq\":\"%s\"}");
	LPCSTR lpFmt2 = "r=%s";
	TCHAR cRData[2048] = {0};
	std::string strRData;
	CHAR cPostData[4096] = {0};
	int nPostDataLen;
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpSign || NULL == lpVfWebQq || NULL == lpSetSignResult)
		return FALSE;

	wsprintf(cRData, lpFmt1, UnicodeToHexStr(lpSign, FALSE).c_str(), lpVfWebQq);
	strRData = EncodeData(cRData, _tcslen(cRData));

	sprintf(cPostData, lpFmt2, strRData.c_str());
	nPostDataLen = strlen(cPostData);

	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, cPostData, 
		nPostDataLen, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpSetSignResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 发送好友消息
BOOL CQQProtocol::SendBuddyMsg(CHttpClient& HttpClient, CBuddyMessage * lpBuddyMsg,	
							   LPCTSTR lpClientId, LPCTSTR lpPSessionId, 
							   CSendBuddyMsgResult * lpSendBuddyMsgResult)
{
 	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
 	LPCTSTR lpszUrl = _T("http://d.web2.qq.com/channel/send_buddy_msg2");
	LPCTSTR lpFontFmt = _T("[\\\"font\\\",{\\\"name\\\":\\\"%s\\\",\\\"size\\\":\\\"%d\\\",\\\"style\\\":[%d,%d,%d],\\\"color\\\":\\\"%s\\\"}]");
 	std::string strRData, strClientId, strPSessionId, strPostData;
 	DWORD dwRespCode;
 	CBuffer RespData;
 	BOOL bRet;
 
 	if (NULL == lpBuddyMsg || NULL == lpClientId
		|| NULL == lpPSessionId || NULL == lpSendBuddyMsgResult)
 		return FALSE;
 
	strClientId = EncodeData(lpClientId, _tcslen(lpClientId));
	strPSessionId = EncodeData(lpPSessionId, _tcslen(lpPSessionId));

	std::wstring strData, strContent;
	std::wstring strFontName;
	WCHAR cBuf[1024] = {0};
	WCHAR cColor[32] = {0};

	for (int i = 0; i < (int)lpBuddyMsg->m_arrContent.size(); i++)
	{
		CContent * lpContent = lpBuddyMsg->m_arrContent[i];
		if (lpContent != NULL)
		{
			if (lpContent->m_nType == CONTENT_TYPE_TEXT)
			{
				strContent += _T("\\\"");
				strContent += UnicodeToHexStr(lpContent->m_strText.c_str(), TRUE);
				strContent += _T("\\\",");
			}
			else if (lpContent->m_nType == CONTENT_TYPE_FONT_INFO)
			{
				strFontName = UnicodeToHexStr(lpContent->m_FontInfo.m_strName.c_str(), TRUE);
				RGBToHexStr(lpContent->m_FontInfo.m_clrText, cColor, sizeof(cColor)/sizeof(WCHAR));

				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, lpFontFmt, strFontName.c_str(), lpContent->m_FontInfo.m_nSize,
					lpContent->m_FontInfo.m_bBold, lpContent->m_FontInfo.m_bItalic,
					lpContent->m_FontInfo.m_bUnderLine, cColor);
				strContent += cBuf;
			}
			else if (lpContent->m_nType == CONTENT_TYPE_FACE)
			{
				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, _T("[\\\"face\\\",%d],"), lpContent->m_nFaceId);
				strContent += cBuf;
			}
			else if (lpContent->m_nType == CONTENT_TYPE_CUSTOM_FACE)
			{
				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, _T("[\\\"cface\\\",\\\"%s\\\"],"), 
					lpContent->m_CFaceInfo.m_strRemoteFileName.c_str());
				strContent += cBuf;
			}
		}
	}

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("{\"to\":%u,"), lpBuddyMsg->m_nToUin);
	strData += cBuf;
	
	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"face\":%d,"), 0);
	strData += cBuf;
	
	strData += _T("\"content\":\"[");
	strData += strContent;
	strData += _T("]\",");

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"msg_id\":%u,"), lpBuddyMsg->m_nMsgId);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"clientid\":\"%s\","), lpClientId);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"psessionid\":\"%s\"}"), lpPSessionId);
	strData += cBuf;

 	strRData = EncodeData(strData.c_str(), strData.size());

	strPostData += "r=";
	strPostData += strRData;
	strPostData += "&clientid=";
	strPostData += strClientId;
	strPostData += "&psessionid=";
	strPostData += strPSessionId;
 
 	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, 
		strPostData.c_str(), strPostData.size(), dwRespCode, NULL, RespData);
 	if (!bRet || dwRespCode != 200)
 		return FALSE;
 
 	bRet = lpSendBuddyMsgResult->Parse(&RespData);
 	if (!bRet)
 		return FALSE;

	return TRUE;
}

// 发送群消息
BOOL CQQProtocol::SendGroupMsg(CHttpClient& HttpClient, CGroupMessage * lpGroupMsg,	
				  LPCTSTR lpClientId, LPCTSTR lpPSessionId, LPCTSTR lpGFaceKey, LPCTSTR lpGFaceSig, CSendGroupMsgResult * lpSendGroupMsgResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
 	LPCTSTR lpszUrl = _T("http://d.web2.qq.com/channel/send_qun_msg2");
	LPCTSTR lpFontFmt = _T("[\\\"font\\\",{\\\"name\\\":\\\"%s\\\",\\\"size\\\":\\\"%d\\\",\\\"style\\\":[%d,%d,%d],\\\"color\\\":\\\"%s\\\"}]");
 	std::string strRData, strClientId, strPSessionId, strPostData;
 	DWORD dwRespCode;
 	CBuffer RespData;
 	BOOL bRet;
 
 	if (NULL == lpGroupMsg || NULL == lpClientId
		|| NULL == lpPSessionId || NULL == lpSendGroupMsgResult)
 		return FALSE;
 
	strClientId = EncodeData(lpClientId, _tcslen(lpClientId));
	strPSessionId = EncodeData(lpPSessionId, _tcslen(lpPSessionId));

	std::wstring strData, strContent;
	std::wstring strFontName;
	WCHAR cBuf[1024] = {0};
	WCHAR cColor[32] = {0};
	BOOL bHasCustomFace = FALSE;

	for (int i = 0; i < (int)lpGroupMsg->m_arrContent.size(); i++)
	{
		CContent * lpContent = lpGroupMsg->m_arrContent[i];
		if (lpContent != NULL)
		{
			if (lpContent->m_nType == CONTENT_TYPE_TEXT)
			{
				strContent += _T("\\\"");
				strContent += UnicodeToHexStr(lpContent->m_strText.c_str(), TRUE);
				strContent += _T("\\\",");
			}
			else if (lpContent->m_nType == CONTENT_TYPE_FONT_INFO)
			{
				strFontName = UnicodeToHexStr(lpContent->m_FontInfo.m_strName.c_str(), TRUE);
				RGBToHexStr(lpContent->m_FontInfo.m_clrText, cColor, sizeof(cColor)/sizeof(WCHAR));

				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, lpFontFmt, strFontName.c_str(), lpContent->m_FontInfo.m_nSize,
					lpContent->m_FontInfo.m_bBold, lpContent->m_FontInfo.m_bItalic,
					lpContent->m_FontInfo.m_bUnderLine, cColor);
				strContent += cBuf;
			}
			else if (lpContent->m_nType == CONTENT_TYPE_FACE)
			{
				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, _T("[\\\"face\\\",%d],"), lpContent->m_nFaceId);
				strContent += cBuf;
			}
			else if (lpContent->m_nType == CONTENT_TYPE_CUSTOM_FACE)
			{
				bHasCustomFace = TRUE;
				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, _T("[\\\"cface\\\",\\\"group\\\",\\\"%s\\\"],"), lpContent->m_CFaceInfo.m_strRemoteFileName.c_str());
				strContent += cBuf;
			}
		}
	}

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("{\"group_uin\":%u,"), lpGroupMsg->m_nToUin);
	strData += cBuf;
	
	if (bHasCustomFace)
	{
		memset(cBuf, 0, sizeof(cBuf));
		wsprintf(cBuf, _T("\"group_code\":%u,"), lpGroupMsg->m_nGroupCode);
		strData += cBuf;

		memset(cBuf, 0, sizeof(cBuf));
		wsprintf(cBuf, _T("\"key\":\"%s\","), lpGFaceKey);
		strData += cBuf;

		memset(cBuf, 0, sizeof(cBuf));
		wsprintf(cBuf, _T("\"sig\":\"%s\","), lpGFaceSig);
		strData += cBuf;
	}

	strData += _T("\"content\":\"[");
	strData += strContent;
	strData += _T("]\",");

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"msg_id\":%u,"), lpGroupMsg->m_nMsgId);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"clientid\":\"%s\","), lpClientId);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"psessionid\":\"%s\"}"), lpPSessionId);
	strData += cBuf;

 	strRData = EncodeData(strData.c_str(), strData.size());
  	
	strPostData += "r=";
	strPostData += strRData;
	strPostData += "&clientid=";
	strPostData += strClientId;
	strPostData += "&psessionid=";
	strPostData += strPSessionId;
 
 	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders,
		strPostData.c_str(), strPostData.size(), dwRespCode, NULL, RespData);
 	if (!bRet || dwRespCode != 200)
 		return FALSE;
 
 	bRet = lpSendGroupMsgResult->Parse(&RespData);
 	if (!bRet)
 		return FALSE;

	return TRUE;
}

// 发送临时会话消息
BOOL CQQProtocol::SendSessMsg(CHttpClient& HttpClient, CSessMessage * lpSessMsg,
							  LPCTSTR lpGroupSig, LPCTSTR lpClientId, LPCTSTR lpPSessionId, 
							  CSendSessMsgResult * lpSendSessMsgResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nAccept-Language: zh-cn\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nContent-Type: application/x-www-form-urlencoded\r\n");
 	LPCTSTR lpszUrl = _T("http://d.web2.qq.com/channel/send_sess_msg2");
	LPCTSTR lpFontFmt = _T("[\\\"font\\\",{\\\"name\\\":\\\"%s\\\",\\\"size\\\":\\\"%d\\\",\\\"style\\\":[%d,%d,%d],\\\"color\\\":\\\"%s\\\"}]");
 	std::string strRData, strClientId, strPSessionId, strPostData;
 	DWORD dwRespCode;
 	CBuffer RespData;
 	BOOL bRet;
 
 	if (NULL == lpSessMsg || NULL == lpGroupSig || NULL == lpClientId
		|| NULL == lpPSessionId || NULL == lpSendSessMsgResult)
 		return FALSE;
 
	strClientId = EncodeData(lpClientId, _tcslen(lpClientId));
	strPSessionId = EncodeData(lpPSessionId, _tcslen(lpPSessionId));

	std::wstring strData, strContent;
	std::wstring strFontName;
	WCHAR cBuf[1024] = {0};
	WCHAR cColor[32] = {0};

	for (int i = 0; i < (int)lpSessMsg->m_arrContent.size(); i++)
	{
		CContent * lpContent = lpSessMsg->m_arrContent[i];
		if (lpContent != NULL)
		{
			if (lpContent->m_nType == CONTENT_TYPE_TEXT)
			{
				strContent += _T("\\\"");
				strContent += UnicodeToHexStr(lpContent->m_strText.c_str(), TRUE);
				strContent += _T("\\\",");
			}
			else if (lpContent->m_nType == CONTENT_TYPE_FONT_INFO)
			{
				strFontName = UnicodeToHexStr(lpContent->m_FontInfo.m_strName.c_str(), TRUE);
				RGBToHexStr(lpContent->m_FontInfo.m_clrText, cColor, sizeof(cColor)/sizeof(WCHAR));

				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, lpFontFmt, strFontName.c_str(), lpContent->m_FontInfo.m_nSize,
					lpContent->m_FontInfo.m_bBold, lpContent->m_FontInfo.m_bItalic,
					lpContent->m_FontInfo.m_bUnderLine, cColor);
				strContent += cBuf;
			}
			else if (lpContent->m_nType == CONTENT_TYPE_FACE)
			{
				memset(cBuf, 0, sizeof(cBuf));
				wsprintf(cBuf, _T("[\\\"face\\\",%d],"), lpContent->m_nFaceId);
				strContent += cBuf;
			}
		}
	}

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("{\"to\":%u,"), lpSessMsg->m_nToUin);
	strData += cBuf;
	
	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"group_sig\":\"%s\","), lpGroupSig);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"face\":%d,"), 0);
	strData += cBuf;
	
	strData += _T("\"content\":\"[");
	strData += strContent;
	strData += _T("]\",");

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"msg_id\":%u,"), lpSessMsg->m_nMsgId);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"service_type\":%u,"), 0);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"clientid\":\"%s\","), lpClientId);
	strData += cBuf;

	memset(cBuf, 0, sizeof(cBuf));
	wsprintf(cBuf, _T("\"psessionid\":\"%s\"}"), lpPSessionId);
	strData += cBuf;

 	strRData = EncodeData(strData.c_str(), strData.size());
  	
	strPostData += "r=";
	strPostData += strRData;
	strPostData += "&clientid=";
	strPostData += strClientId;
	strPostData += "&psessionid=";
	strPostData += strPSessionId;
 
 	bRet = HttpPost(HttpClient, lpszUrl, lpszReqHeaders, 
		strPostData.c_str(), strPostData.size(),dwRespCode, NULL, RespData);
 	if (!bRet || (dwRespCode < 200 || dwRespCode >= 400))
 		return FALSE;
 
 	bRet = lpSendSessMsgResult->Parse(&RespData);
 	if (!bRet)
 		return FALSE;

	return TRUE;
}

// 获取头像图片
BOOL CQQProtocol::GetHeadPic(CHttpClient& HttpClient, BOOL bIsBuddy,
							 UINT nQQUin, LPCTSTR lpVfWebQq, CBuffer * lpFacePic)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://web2.qq.com/webqq.html\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://face%d.web.qq.com/cgi/svr/face/getface?cache=0&type=%d&fid=0&uin=%u&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpVfWebQq || NULL == lpFacePic)
		return FALSE;

	int nType = bIsBuddy ? 11 : 14;

	srand((UINT)time(NULL));
	int nRandom = rand() % 9 + 1;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nRandom, nType, nQQUin, lpVfWebQq, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || !(dwRespCode >= 200 && dwRespCode < 300))
		return FALSE;

	lpFacePic->Release();
	bRet = lpFacePic->Add(RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取好友聊天图片
BOOL CQQProtocol::GetBuddyChatPic(CHttpClient& HttpClient, UINT nMsgId,
								  LPCTSTR lpFileName, UINT nQQUin, LPCTSTR lpClientId,
								  LPCTSTR lpPSessionId, CBuffer * lpBuddyPic)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://web.qq.com/?ADTAG=DESKTOP\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/get_cface2?lcid=%u&guid=%s&to=%u&count=5&time=1&clientid=%s&psessionid=%s");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpFileName || NULL == lpClientId 
		|| NULL == lpPSessionId || NULL == lpBuddyPic)
		return FALSE;

	wsprintf(szUrl, lpFmt, nMsgId, lpFileName, nQQUin, lpClientId, lpPSessionId);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || !(dwRespCode >= 200 && dwRespCode < 300))
		return FALSE;

	lpBuddyPic->Release();
	bRet = lpBuddyPic->Add(RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取好友离线聊天图片
BOOL CQQProtocol::GetBuddyOffChatPic(CHttpClient& HttpClient, LPCTSTR lpFileName, UINT nQQUin, 
									 LPCTSTR lpClientId, LPCTSTR lpPSessionId, CBuffer * lpBuddyPic)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://web.qq.com/?ADTAG=DESKTOP\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/get_offpic2?file_path=%s&f_uin=%u&clientid=%s&psessionid=%s");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpFileName || NULL == lpClientId 
		|| NULL == lpPSessionId || NULL == lpBuddyPic)
		return FALSE;

	wsprintf(szUrl, lpFmt, lpFileName, nQQUin, lpClientId, lpPSessionId);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || !(dwRespCode >= 200 && dwRespCode < 300))
		return FALSE;

	lpBuddyPic->Release();
	bRet = lpBuddyPic->Add(RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取群聊天图片
BOOL CQQProtocol::GetGroupChatPic(CHttpClient& HttpClient, UINT nGroupId,
								  UINT nQQUin, LPCTSTR lpServer, int nPort, UINT nFileId, 
								  LPCTSTR lpFileName, LPCTSTR lpVfWebQq, CBuffer * lpGroupPic)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://web.qq.com/?ADTAG=DESKTOP\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\n");
	LPCTSTR lpFmt = _T("http://web.qq.com/cgi-bin/get_group_pic?type=0&gid=%u&uin=%u&rip=%s&rport=%d&fid=%u&pic=%s&vfwebqq=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpServer || NULL == lpFileName 
		|| NULL == lpVfWebQq || NULL == lpGroupPic)
		return FALSE;

	wsprintf(szUrl, lpFmt, nGroupId, nQQUin, 
		lpServer, nPort, nFileId, lpFileName, lpVfWebQq);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || !(dwRespCode >= 200 && dwRespCode < 300))
		return FALSE;

	lpGroupPic->Release();
	bRet = lpGroupPic->Add(RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 改变状态
BOOL CQQProtocol::ChangeStatus(CHttpClient& HttpClient, QQ_STATUS nStatus,
							   LPCTSTR lpClientId, LPCTSTR lpPSessionId, 
							   CChangeStatusResult * lpChangeStatusResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/change_status2?newstatus=%s&clientid=%s&psessionid=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpClientId || NULL == lpPSessionId 
		|| NULL == lpChangeStatusResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	LPCTSTR lpStatusStr = ConvertToQQStatusStr(nStatus);

	wsprintf(szUrl, lpFmt, lpStatusStr, lpClientId, lpPSessionId, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpChangeStatusResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取临时会话信令
BOOL CQQProtocol::GetC2CMsgSignal(CHttpClient& HttpClient, UINT nGroupId,
								  UINT nToUin, LPCTSTR lpClientId, LPCTSTR lpPSessionId, 
								  CGetC2CMsgSigResult * lpGetC2CMsgSigResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/get_c2cmsg_sig2?id=%u&to_uin=%u&service_type=0&clientid=%s&psessionid=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpClientId || NULL == lpPSessionId 
		|| NULL == lpGetC2CMsgSigResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, nGroupId, nToUin, lpClientId, lpPSessionId, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpGetC2CMsgSigResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 获取群表情信令
BOOL CQQProtocol::GetGroupFaceSignal(CHttpClient& HttpClient, LPCTSTR lpClientId, LPCTSTR lpPSessionId, 
									 CGetGroupFaceSigResult * lpGetGroupFaceSigResult)
{
	LPCTSTR lpszReqHeaders = _T("Accept: */*\r\nReferer: http://d.web2.qq.com/proxy.html?v=20110331002&callback=2\r\nAccept-Language: zh-cn\r\n");
	LPCTSTR lpFmt = _T("http://d.web2.qq.com/channel/get_gface_sig2?clientid=%s&psessionid=%s&t=%u");
	TCHAR szUrl[MAX_URL_LEN] = {0};
	DWORD dwRespCode;
	CBuffer RespData;
	BOOL bRet;

	if (NULL == lpClientId || NULL == lpPSessionId 
		|| NULL == lpGetGroupFaceSigResult)
		return FALSE;

	time_t t;
	t = time(NULL);

	wsprintf(szUrl, lpFmt, lpClientId, lpPSessionId, t);

	bRet = HttpGet(HttpClient, szUrl, lpszReqHeaders, dwRespCode, NULL, RespData);
	if (!bRet || dwRespCode != 200)
		return FALSE;

	bRet = lpGetGroupFaceSigResult->Parse(&RespData);
	if (!bRet)
		return FALSE;

	return TRUE;
}

// 上传自定义表情
BOOL CQQProtocol::UploadCustomFace(CHttpClient& HttpClient, LPCTSTR lpFileName,
								   LPCTSTR lpVfWebQq, CUploadCustomFaceResult * lpResult)
{
	LPCTSTR lpszUrl = _T("http://up.web2.qq.com/cgi-bin/cface_upload");
 	DWORD dwRespCode;
 	CBuffer RespData;
 	BOOL bRet;
 
 	if (NULL == lpFileName || NULL == *lpFileName || NULL == lpVfWebQq || NULL == lpResult)
 		return FALSE;
 
	CHAR * lpImageData = NULL;
	LONG lImageSize = 0;
	bRet = File_ReadAll(lpFileName, &lpImageData, &lImageSize);
	if (!bRet)
		return FALSE;

	// 构建Http请求体的Post数据
	std::string strBoundary = "----WebKitFormBoundarygomvAbMHe1VA6guI";
	std::string strBoundary2 = "--" + strBoundary + "\r\n";
	std::string strVfWebQq = UnicodeToUtf8(tstring(lpVfWebQq));
	std::string strFileName = UnicodeToUtf8(ZYM::CPath::GetFileName(lpFileName));
	std::string strMimeType = UnicodeToUtf8(GetMimeTypeByExtension(ZYM::CPath::GetExtension(lpFileName).c_str()));

	CBuffer postData;

	postData.Add(strBoundary2.c_str());
	postData.Add("Content-Disposition: form-data; name=\"custom_face\"; filename=\"");
	postData.Add(strFileName.c_str());
	postData.Add("\"\r\n");

	postData.Add("Content-Type: ");
	postData.Add(strMimeType.c_str());
	postData.Add("\r\n\r\n");

	postData.Add((const BYTE *)lpImageData, lImageSize);
	postData.Add("\r\n");

	postData.Add(strBoundary2.c_str());
	postData.Add("Content-Disposition: form-data; name=\"f\"\r\n\r\n");
	postData.Add("EQQ.View.ChatBox.uploadCustomFaceCallback\r\n");

	postData.Add(strBoundary2.c_str());
	postData.Add("Content-Disposition: form-data; name=\"vfwebqq\"\r\n\r\n");
	postData.Add(strVfWebQq.c_str());
	postData.Add("\r\n");

	postData.Add("--");
	postData.Add(strBoundary.c_str());
	postData.Add("--\r\n\r\n");

	// 构建Http请求头
	TCHAR cContentType[256] = {0};
	wsprintf(cContentType, _T("Content-Type: multipart/form-data; boundary=%s\r\n"), _T("----WebKitFormBoundarygomvAbMHe1VA6guI"));

	TCHAR cContentLength[256] = {0};
	wsprintf(cContentLength, _T("Content-Length: %u\r\n"), postData.GetSize());

	tstring strReqHeaders;
	strReqHeaders = _T("Accept: Accept: image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, application/x-ms-application, application/x-ms-xbap, application/vnd.ms-xpsdocument, application/xaml+xml, */*\r\n");
	strReqHeaders += _T("Referer: http://web2.qq.com/webqq.html\r\n");
	strReqHeaders += _T("Accept-Language: zh-cn\r\n");
	strReqHeaders += cContentType;
	strReqHeaders += _T("Accept-Encoding: gzip, deflate\r\n");
	strReqHeaders += cContentLength;
	strReqHeaders += _T("Connection: keep-alive\r\n");
	strReqHeaders += _T("Cache-Control: no-cache\r\n");
	
 	bRet = HttpBigPost(HttpClient, lpszUrl, strReqHeaders.c_str(),
		(const CHAR *)postData.GetData(), postData.GetSize(), dwRespCode, NULL, RespData);
 	if (!bRet || dwRespCode != 200)
 		return FALSE;
 
 	return lpResult->Parse(&RespData);
}

BOOL CQQProtocol::HttpReq(CHttpClient& HttpClient, LPCTSTR lpszUrl, 
			 LPCTSTR lpszReqHeaders, const CHAR * lpPostData, DWORD dwPostDataLen, 
			 DWORD& dwRespCode, std::vector<tstring>* arrRespHeader, CBuffer& RespData)
{
	HTTP_REQ_METHOD nReqMethod;
	CHAR cBuf[1024] = {0};
	DWORD dwBufLen = 1024;
	DWORD dwRecvLen;
	BOOL bRet;

	dwRespCode = 0;
	if (arrRespHeader != NULL)
		arrRespHeader->clear();
	RespData.Release();

	if (lpPostData != NULL && dwPostDataLen > 0)
		nReqMethod = REQ_METHOD_POST;
	else
		nReqMethod = REQ_METHOD_GET;

	bRet = HttpClient.OpenRequest(lpszUrl, nReqMethod);
	if (!bRet)
		return FALSE;

	if (lpszReqHeaders != NULL)
		HttpClient.AddReqHeaders(lpszReqHeaders);
	
	bRet = HttpClient.SendRequest(lpPostData, dwPostDataLen);
	if (!bRet)
	{
		HttpClient.CloseRequest();
		return FALSE;
	}

	dwRespCode = HttpClient.GetRespCode();

	do
	{
		bRet = HttpClient.GetRespBodyData(cBuf, dwBufLen, dwRecvLen);
		if (!bRet)
		{
			HttpClient.CloseRequest();
			return FALSE;
		}

		if (dwRecvLen == 0)
		{
			break;
		}
		else
		{
			RespData.Add((const BYTE *)cBuf, dwRecvLen);
		}
	} while (1);

	if (arrRespHeader != NULL)
	{
		tstring strRespHeader = HttpClient.GetRespHeader();
		tstring strLine;
		int nStart = 0;

		std::wstring::size_type nPos = strRespHeader.find(_T("\r\n"), nStart);
		while (nPos != std::wstring::npos)
		{
			strLine = strRespHeader.substr(nStart, nPos - nStart);
			if (strLine != _T(""))
				arrRespHeader->push_back(strLine);
			nStart = nPos + 2;
			nPos = strRespHeader.find(_T("\r\n"), nStart);
		}
	}

	HttpClient.CloseRequest();

	return TRUE;
}

BOOL CQQProtocol::HttpGet(CHttpClient& HttpClient, LPCTSTR lpszUrl, 
			 LPCTSTR lpszReqHeaders, DWORD& dwRespCode, 
			 std::vector<tstring>* arrRespHeader, CBuffer& RespData)
{
	return HttpReq(HttpClient, lpszUrl, lpszReqHeaders, 
		NULL, 0, dwRespCode, arrRespHeader, RespData);
}

BOOL CQQProtocol::HttpPost(CHttpClient& HttpClient, LPCTSTR lpszUrl, 
			  LPCTSTR lpszReqHeaders, const CHAR * lpPostData, DWORD dwPostDataLen, 
			  DWORD& dwRespCode, std::vector<tstring>* arrRespHeader, CBuffer& RespData)
{
	return HttpReq(HttpClient, lpszUrl, lpszReqHeaders, 
		lpPostData, dwPostDataLen, dwRespCode, arrRespHeader, RespData);
}

BOOL CQQProtocol::HttpBigPost(CHttpClient& HttpClient, LPCTSTR lpszUrl, 
							  LPCTSTR lpszReqHeaders, const CHAR * lpPostData, DWORD dwPostDataLen, 
							  DWORD& dwRespCode, std::vector<tstring>* arrRespHeader, CBuffer& RespData)
{
	const CHAR * pSendBuf;
	DWORD dwSendBufLen = 8192, dwSendLen;
	DWORD dwBlock, dwRemainder;
	CHAR cRecvBuf[8192] = {0};
	DWORD dwRecvBufLen = sizeof(cRecvBuf);
	DWORD dwRecvLen;
	BOOL bRet;

	dwRespCode = 0;
	if (arrRespHeader != NULL)
		arrRespHeader->clear();
	RespData.Release();

	if (NULL == lpPostData || dwPostDataLen <= 0)
		return FALSE;

	bRet = HttpClient.OpenRequest(lpszUrl, REQ_METHOD_POST);
	if (!bRet)
		return FALSE;

	if (lpszReqHeaders != NULL)
		HttpClient.AddReqHeaders(lpszReqHeaders);

	bRet = HttpClient.SendRequestEx(dwPostDataLen);
	if (!bRet)
	{
		HttpClient.CloseRequest();
		return FALSE;
	}

	pSendBuf = lpPostData;
	dwBlock = dwPostDataLen / dwSendBufLen;
	dwRemainder = dwPostDataLen % dwSendBufLen;

	for (DWORD i = 0; i < dwBlock; i++)
	{
		bRet = HttpClient.SendReqBodyData(pSendBuf, dwSendBufLen, dwSendLen);
		if (!bRet || dwSendLen != dwSendBufLen)
		{
			HttpClient.EndSendRequest();
			HttpClient.CloseRequest();
			return FALSE;
		}
		pSendBuf += dwSendLen;
	}

	
	if (dwRemainder != 0)
	{
		bRet = HttpClient.SendReqBodyData(pSendBuf, dwRemainder, dwSendLen);
		if (!bRet || dwSendLen != dwRemainder)
		{
			HttpClient.EndSendRequest();
			HttpClient.CloseRequest();
			return FALSE;
		}
	}

	HttpClient.EndSendRequest();
	
	dwRespCode = HttpClient.GetRespCode();
	if (dwRespCode != 200)
	{
		HttpClient.CloseRequest();
		return FALSE;
	}

	do
	{
		bRet = HttpClient.GetRespBodyData(cRecvBuf, dwRecvBufLen, dwRecvLen);
		if (!bRet)
		{
			HttpClient.CloseRequest();
			return FALSE;
		}

		if (dwRecvLen == 0)
		{
			break;
		}
		else
		{
			RespData.Add((const BYTE *)cRecvBuf, dwRecvLen);
		}
	} while (1);

	if (arrRespHeader != NULL)
	{
		tstring strRespHeader = HttpClient.GetRespHeader();
		tstring strLine;
		int nStart = 0;

		std::wstring::size_type nPos = strRespHeader.find(_T("\r\n"), nStart);
		while (nPos != std::wstring::npos)
		{
			strLine = strRespHeader.substr(nStart, nPos - nStart);
			if (strLine != _T(""))
				arrRespHeader->push_back(strLine);
			nStart = nPos + 2;
			nPos = strRespHeader.find(_T("\r\n"), nStart);
		}
	}

	HttpClient.CloseRequest();

	return TRUE;
}

std::string CQQProtocol::EncodeData(const CHAR * lpData, int nLen)
{
	CHAR szBuf[16];
	CHAR * lpUtf8Data;
	std::string strUtf8Data;

	for (int i = 0; i < nLen; i++)
	{
		if (my_isalnum((unsigned char)lpData[i])/* || '_' == lpData[i]*/)
		{
			strUtf8Data += lpData[i];
		}
		else
		{
			sprintf(szBuf, "%%%02X", (unsigned char)lpData[i]);
			strUtf8Data += szBuf;
		}
	}

	return strUtf8Data;
}

std::string CQQProtocol::EncodeData(const WCHAR * lpData, int nLen)
{
	CHAR * lpUtf8Data;
	std::string strUtf8Data;

	lpUtf8Data = UnicodeToUtf8(lpData);
	if (NULL == lpUtf8Data)
		return "";

	strUtf8Data = EncodeData(lpUtf8Data, strlen(lpUtf8Data));

	delete []lpUtf8Data;

	return strUtf8Data;
}

std::wstring CQQProtocol::UnicodeToHexStr(const WCHAR * lpStr, BOOL bDblSlash)
{
	static const WCHAR * lpHexStr = _T("0123456789abcdef");
	std::wstring strRet = _T("");
	WCHAR * lpSlash;

	if (NULL == lpStr || NULL == *lpStr)
		return strRet;

	lpSlash = (bDblSlash ? _T("\\\\u") : _T("\\u"));

	for (int i = 0; i < (int)wcslen(lpStr); i++)
	{
		if (my_isalnum((WCHAR)lpStr[i]))	// 检测指定字符是否是字母(A-Z，a-z)或数字(0-9)
		{
			strRet += lpStr[i];
		}
		else
		{
			CHAR * lpChar = (CHAR *)&lpStr[i];

			strRet += lpSlash;
			strRet += lpHexStr[((unsigned char)(*(lpChar+1)) >> 4) & 0x0f];
			strRet += lpHexStr[(unsigned char)(*(lpChar+1)) & 0x0f];
			strRet += lpHexStr[((unsigned char)(*lpChar) >> 4) & 0x0f];
			strRet += lpHexStr[(unsigned char)(*lpChar) & 0x0f];
		}
	}

	return strRet;
}

// 计算第一次登录的密码hash参数
BOOL CQQProtocol::CalcPwdHash(LPCTSTR lpQQPwd, LPCTSTR lpVerifyCode, 
							  const CHAR * lpPtUin, int nPtUinLen, TCHAR * lpPwdHash, int nLen)
{
	CHAR cQQPwd[128] = {0};
	CHAR cVerifyCode[128] = {0};
	CHAR cHex[36] = {0};
	CHAR cTemp[256] = {0};
	const byte * lpDigest;
	MD5 md5;

	// UPPER(HEX(MD5(UPPER(HEX(MD5(MD5(密码) + PtUin))) + UPPER(验证码))))

	if (NULL == lpQQPwd || NULL == lpVerifyCode
		|| NULL == lpPtUin || nPtUinLen <= 0
		|| NULL == lpPwdHash || nLen <= 0)
		return FALSE;

	UnicodeToUtf8(lpQQPwd, cQQPwd, sizeof(cQQPwd));
	UnicodeToUtf8(lpVerifyCode, cVerifyCode, sizeof(cVerifyCode));

	md5.reset();
	md5.update((const void *)cQQPwd, strlen(cQQPwd));
	lpDigest = md5.digest();

	memset(cTemp, 0, sizeof(cTemp));
	memcpy(cTemp, lpDigest, 16);
	memcpy(&cTemp[16], lpPtUin, nPtUinLen);

	md5.reset();
	md5.update((const void *)cTemp, 16 + nPtUinLen);
	lpDigest = md5.digest();

	ToHexStr((const CHAR *)lpDigest, 16, cHex, sizeof(cHex));
	_strupr(cHex);
	_strupr(cVerifyCode);

	int nHexLen = strlen(cHex);
	int nVerifyCodeLen = strlen(cVerifyCode);
	memset(cTemp, 0, sizeof(cTemp));
	memcpy(cTemp, cHex, nHexLen);
	memcpy(&cTemp[nHexLen], cVerifyCode, nVerifyCodeLen);

	md5.reset();
	md5.update((const void *)cTemp, nHexLen + nVerifyCodeLen);
	lpDigest = md5.digest();

	ToHexStr((const CHAR *)lpDigest, 16, cHex, sizeof(cHex));
	_strupr(cHex);

	Utf8ToUnicode(cHex, lpPwdHash, nLen);

	return TRUE;
}

// 计算获取好友/群列表的hash参数
std::string CQQProtocol::CalcHash(UINT nQQUin, LPCTSTR lpPtWebQq)
{
	CHAR b[256] = {0};
	sprintf(b, "%u", nQQUin);

	CHAR * lpText = UnicodeToUtf8(lpPtWebQq);
	if (NULL == lpText)
		return "";
	std::string j = lpText;
	delete []lpText;

	std::string a = j + "password error";
	std::string i = "";
	for (;;)
	{
		if (i.size() <= a.size()) 
		{
			i += b;
			if (i.size() == a.size())
				break;
		} 
		else 
		{
			i = i.substr(0, a.size());
			break;
		}
	}

	int E_size = (int)i.size();
	CHAR * E = new CHAR[E_size];
	for (int c = 0; c < E_size; c++)
		E[c] = (CHAR)(i[c] ^ a[c]);
	
	char m[] = "0123456789ABCDEF";
	i = "";
	for (int c = 0; c < E_size; c++)
	{
		i += m[E[c] >> 4 & 15];
		i += m[E[c] & 15];
	}

	delete []E;

	return i;
}

/* JS Hash代码
P = function (b, j) {
	for (var a = j + "password error", i = "", E = []; ;)
		if (i.length <= a.length) {
			if (i += b, i.length == a.length)
				break
		} else {
			i = i.slice(0, a.length);
			break
		}

		for (var c = 0; c < i.length; c++)
			E[c] = i.charCodeAt(c) ^ a.charCodeAt(c);

		a = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];
		i = "";
		for (c = 0; c < E.length; c++)
			i += a[E[c] >> 4 & 15], i += a[E[c] & 15];
		return i
}
*/
