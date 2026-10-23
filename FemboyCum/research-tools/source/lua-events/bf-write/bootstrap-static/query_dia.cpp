// Query a matching public PDB as data. No guest image is loaded or executed.
#define NOMINMAX
#include <windows.h>
#include <dia2.h>
#include <cstdio>
#include <cstdlib>

using GetClassObject = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

static void fail(const char* what, HRESULT status) {
    std::fprintf(stderr, "%s: 0x%08lx\n", what,
                 static_cast<unsigned long>(status));
    std::exit(1);
}

static void print_symbol(const char* label, IDiaSymbol* symbol,
                         LONG displacement = 0) {
    if (!symbol) {
        std::printf("%s none\n", label);
        return;
    }
    DWORD tag = 0, rva = 0, cc = 0;
    ULONGLONG length = 0;
    BSTR name = nullptr;
    symbol->get_symTag(&tag);
    symbol->get_relativeVirtualAddress(&rva);
    symbol->get_length(&length);
    symbol->get_name(&name);
    std::printf("%s tag=%lu rva=0x%08lx displacement=%ld length=0x%llx ",
                label, static_cast<unsigned long>(tag),
                static_cast<unsigned long>(rva),
                static_cast<long>(displacement),
                static_cast<unsigned long long>(length));
    std::printf("name=%ls\n", name ? name : L"<none>");
    if (name) SysFreeString(name);
    IDiaSymbol* type = nullptr;
    if (symbol->get_type(&type) == S_OK && type) {
        HRESULT hr = type->get_callingConvention(&cc);
        std::printf("%s type_calling_convention=%s%lu\n", label,
                    hr == S_OK ? "" : "unavailable:",
                    static_cast<unsigned long>(cc));
        type->Release();
    }
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        std::fprintf(stderr, "usage: query_dia.exe installed-msdia140.dll exact-pdb\n");
        return 2;
    }
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) fail("CoInitializeEx", hr);
    HMODULE dll = LoadLibraryExW(argv[1], nullptr,
                                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!dll) fail("load installed DIA provider", HRESULT_FROM_WIN32(GetLastError()));
    auto get_class = reinterpret_cast<GetClassObject>(
        GetProcAddress(dll, "DllGetClassObject"));
    if (!get_class) fail("DIA DllGetClassObject", HRESULT_FROM_WIN32(GetLastError()));
    IClassFactory* factory = nullptr;
    hr = get_class(CLSID_DiaSource, IID_IClassFactory,
                   reinterpret_cast<void**>(&factory));
    if (FAILED(hr)) fail("DIA class factory", hr);
    IDiaDataSource* source = nullptr;
    hr = factory->CreateInstance(nullptr, IID_IDiaDataSource,
                                 reinterpret_cast<void**>(&source));
    if (FAILED(hr)) fail("DIA source", hr);
    factory->Release();
    hr = source->loadDataFromPdb(argv[2]);
    if (FAILED(hr)) fail("load PDB", hr);
    IDiaSession* session = nullptr;
    hr = source->openSession(&session);
    if (FAILED(hr)) fail("open DIA session", hr);
    IDiaSymbol* global = nullptr;
    hr = session->get_globalScope(&global);
    if (FAILED(hr)) fail("global scope", hr);
    GUID guid = {};
    DWORD age = 0;
    hr = global->get_guid(&guid);
    if (FAILED(hr)) fail("PDB GUID", hr);
    hr = global->get_age(&age);
    if (FAILED(hr)) fail("PDB age", hr);
    wchar_t guid_text[48] = {};
    StringFromGUID2(guid, guid_text, 48);
    std::printf("PDB guid=%ls age=%lu\n", guid_text,
                static_cast<unsigned long>(age));
    const DWORD targets[] = {
        0x4a4dd, 0x385f3,
        0x4a538, 0x953ef, 0x455a5, 0x4a440, 0x95419,
        0xb4f24, 0x4fb30, 0x43ac0, 0x35caf, 0x6a807, 0x3f880,
        0x35f75, 0x7ffd0, 0x116846, 0x3ee10, 0x359d5,
        0x79d60, 0x35995, 0x2a00d, 0x43a50,
        0xbe8b1, 0x4ca80, 0x4fc00, 0x95443, 0x4faf0, 0x4560d,
        0x137210, 0x13720c, 0x137214, 0x137218, 0x137358,
        0x13b290, 0x13b294, 0x13b298, 0x13b2a0, 0x1397bc,
    };
    const enum SymTagEnum tags[] = {SymTagNull, SymTagFunction,
                                    SymTagPublicSymbol, SymTagThunk};
    const char* labels[] = {"any", "function", "public", "thunk"};
    for (DWORD rva : targets) {
        std::printf("TARGET 0x%08lx\n", static_cast<unsigned long>(rva));
        for (unsigned i = 0; i < 4; ++i) {
            IDiaSymbol* symbol = nullptr;
            LONG displacement = 0;
            hr = session->findSymbolByRVAEx(rva, tags[i], &symbol,
                                            &displacement);
            if (hr == S_OK && symbol) {
                print_symbol(labels[i], symbol, displacement);
                symbol->Release();
            } else {
                std::printf("%s none hr=0x%08lx\n", labels[i],
                            static_cast<unsigned long>(hr));
            }
        }
    }
    IDiaEnumSymbols* symbols = nullptr;
    hr = global->findChildren(SymTagPublicSymbol, nullptr, nsNone, &symbols);
    if (hr == S_OK && symbols) {
        IDiaSymbol* symbol = nullptr;
        ULONG fetched = 0;
        while (symbols->Next(1, &symbol, &fetched) == S_OK && fetched == 1) {
            DWORD rva = 0;
            if (symbol->get_relativeVirtualAddress(&rva) == S_OK) {
                for (unsigned j = 0; j < 2; ++j) {
                    DWORD target = targets[j];
                    if (rva >= target - 0x100 && rva < target + 0x200) {
                        print_symbol("nearby_public", symbol);
                        break;
                    }
                }
            }
            symbol->Release();
        }
        symbols->Release();
    }
    global->Release();
    session->Release();
    source->Release();
    FreeLibrary(dll);
    CoUninitialize();
    return 0;
}
