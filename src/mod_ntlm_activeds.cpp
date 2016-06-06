extern "C" {
#include "mod_ntlm.h"
}

#include <activeds.h>
#pragma comment (lib, "activeds.lib")
#import <activeds.tlb> no_auto_exclude auto_rename named_guids

static char *utf8(apr_pool_t *p, wchar_t* wstr)
{
    const UINT codepage = CP_UTF8;
    int size = 0;
	char *retval = NULL;

    if (size = WideCharToMultiByte(codepage, 0, wstr, -1, NULL, 0, NULL, NULL)) {
        if (retval = (char*)apr_palloc(p, size)) {
            if (WideCharToMultiByte(codepage, 0, wstr, -1, retval, size, NULL, NULL)) {
                return retval;
            }
        }
    }

    return NULL;
}

extern "C"
void SetRemoteUserAttribute(sspi_auth_ctx* ctx)
{
    HRESULT hr;

	if (ctx->crec->sspi_remoteuserattribute == NULL) {
        return;
	}

    CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_SPEED_OVER_MEMORY);

    try {
        ActiveDs::IADsADSystemInfoPtr pADsys;
        ActiveDs::IADsUserPtr pADUser;
        _bstr_t dn;
        _bstr_t username;

        hr = pADsys.CreateInstance(ActiveDs::CLSID_ADSystemInfo);
        if (SUCCEEDED(hr)) {
            dn = pADsys->GetUserName();
            
            hr = ADsGetObject(_bstr_t(L"LDAP://") + dn,
                              ActiveDs::IID_IADsUser,
                              (void**) &pADUser);
            if (SUCCEEDED(hr)) {
                username = pADUser->Get(_bstr_t(ctx->crec->sspi_remoteuserattribute));
                
                ctx->scr->username = utf8(ctx->r->connection->pool, username);
                ctx->r->user = ctx->scr->username;
            }
        }
    } catch (_com_error err) {
        /* Do nothing if error*/
    }

    CoUninitialize();
}

